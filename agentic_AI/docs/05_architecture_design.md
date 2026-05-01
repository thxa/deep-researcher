# 05 — Designing Neural Network Architectures from Scratch

A deep-dive reference for architects who need to reason about every structural choice in a neural network, from individual layers to whole-system scaling laws.

---

## Table of Contents

1. [Architecture Design Principles](#1-architecture-design-principles)
2. [Designing CNNs](#2-designing-cnns)
3. [Designing Transformers](#3-designing-transformers)
4. [Hybrid Architectures](#4-hybrid-architectures)
5. [Neural Architecture Search](#5-neural-architecture-search)
6. [Scaling Laws & Compute-Optimal Models](#6-scaling-laws--compute-optimal-models)
7. [Memory & Compute Optimization](#7-memory--compute-optimization)
8. [Architecture Visualization & Documentation](#8-architecture-visualization--documentation)

---

## 1. Architecture Design Principles

### 1.1 Depth vs. Width

The two fundamental axes for growing a network are **depth** (more layers) and **width** (more channels / hidden units). Each has distinct trade-offs:

| Axis | Benefit | Cost | Diminishing Returns |
|------|---------|------|---------------------|
| **Depth** | Hierarchical feature abstraction; reuses parameters across stages | Vanishing/exploding gradients; longer critical path; harder to optimize | ~3-4× after ResNet-152 |
| **Width** | More representational capacity per layer; easier to parallelize | Quadratic parameter growth in fully-connected layers; FLOPs blow up | ~2× after reasonable width |

**Guidelines:**
- Prefer depth over width for visual/spatial tasks (CNNs) — deeper hierarchies capture more abstract features.
- Prefer width for tasks requiring dense association (language modeling, recommendation) — wider embeddings can memorize more co-occurrences.
- For a fixed compute budget *C*, a rough balance is: depth ~ O(C^{0.35}), width ~ O(C^{0.35}), with the rest allocated to data or sequence length.

### 1.2 Residual Connections

Without skip connections, a layer must learn the full transformation `H(x)`. With residuals, it only needs to learn the *delta* `F(x) = H(x) - x`, which is far easier to optimize.

```
              Residual Block
              ===============

       x ──────────┬─────────────────────┐ (+)
       │           │                     │
       │     ┌─────▼─────┐               │
       │     │  Conv/BN   │               │
       │     │  + ReLU    │               │
       │     └─────┬──────┘               │
       │     ┌─────▼─────┐               │
       │     │  Conv/BN   │               │
       │     └─────┬──────┘               │
       │           │  F(x)                │
       │           └────────► (+) ────────┘──► ReLU ──► out = ReLU(F(x)+x)

  Key insight: if F(x)→0, output → x (identity). The network
  degrades gracefully — deeper models are at least as good as
  shallower ones, never worse.
```

**Variants:**
- **Pre-activation** (ResNet-v2): BN → ReLU → Conv, skip connection on the *input* to the block. Improves gradient flow.
- **Dense connections** (DenseNet): each layer receives concatenated outputs from *all* prior layers.
- **Highway networks**: learnable gates controlling how much information flows through the skip vs. transform path.

### 1.3 Normalization

| Method | Normalizes Over | Trainable Params | Use Case |
|--------|-----------------|-------------------|----------|
| BatchNorm | (N, H, W) per channel | γ, β per channel | CNNs with large batch sizes |
| LayerNorm | (C, H, W) per sample | γ, β per channel | Transformers, RNNs |
| InstanceNorm | (H, W) per channel per sample | γ, β per channel | Style transfer |
| GroupNorm | groups of C, (H, W) per sample | γ, β per channel | Small-batch CNNs |
| RMSNorm | (C) per sample — only scale | 1 weight per dim | LLMs (LLaMA, etc.) |

**Design rules:**
- Use **BatchNorm** in CNNs when batch size ≥ 16; it provides a mild regularizing effect due to batch statistics noise.
- Use **LayerNorm** or **RMSNorm** in Transformers and RNNs; they are independent of batch dimension.
- Place normalization *before* the nonlinearity (pre-norm) for easiest training; post-norm can achieve slightly better final accuracy but is harder to stabilize.

### 1.4 Activation Functions

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  Common Activation Functions — Shape & Properties                │
  │                                                                  │
  │  ReLU:     ┐        Pros: cheap, sparse, no saturation          │
  │            │        Cons: dead neurons, unbounded +             │
  │        ────┘───     Range: [0, ∞)                               │
  │                                                                  │
  │  GELU:     ┐        Pros: smooth, approximatesPhi(x), good for   │
  │            │             Transformers                            │
  │        ────┘───     Cons: slightly more expensive               │
  │                                                                  │
  │  Swish:    ┐        Pros: non-monotonic, smooth, better W&R     │
  │    (SiLU)  │        Cons: more expensive than ReLU              │
  │        ────┘───     Range: (~-0.28, ∞)                          │
  │                                                                  │
  │  Mish:     ┐        Pros: smooth, best W&R on some benchmarks   │
  │            │        Cons: expensive (tanh + softplus)           │
  │        ────┘───                                                 │
  │                                                                  │
  │  GLU variants (SwiGLU, GeGLU): gate = σ(Wx+b) ⊙ f(Vx+c)       │
  │    → dominant in LLMs (LLaMA, PaLM) — better capacity/param    │
  └──────────────────────────────────────────────────────────────────┘
```

**Selection heuristic:**
- **CNNs**: ReLU (fastest), Swish/SiLU (better accuracy on EfficientNet-family).
- **Transformers / LLMs**: GELU (GPT-2/BERT), SwiGLU (LLaMA/PaLM — best quality per parameter).
- **Edge / quantized models**: ReLU or ReLU6 (hardware-friendly, no transcendental ops).

---

## 2. Designing CNNs

### 2.1 VGG-Style: Stack Simplicity

The VGG design philosophy: use only 3×3 convolutions stacked deeply, doubling channels after each pooling stage.

```
    VGG-Style Architecture
    ======================

    Input (224×224×3)
        │
        ├─ [3×3 conv, 64] ×2  ──► 224×224×64
        ├─ MaxPool 2×2
        ├─ [3×3 conv, 128] ×2 ──► 112×112×128
        ├─ MaxPool 2×2
        ├─ [3×3 conv, 256] ×3 ──► 56×56×256
        ├─ MaxPool 2×2
        ├─ [3×3 conv, 512] ×3 ──► 28×28×512
        ├─ MaxPool 2×2
        ├─ [3×3 conv, 512] ×3 ──► 14×14×512
        ├─ MaxPool 2×2
        │
        ├─ Flatten ──► 7×7×512 = 25,088
        ├─ FC-4096
        ├─ FC-4096
        └─ FC-1000

    Tradeoff: ~143M params, mostly in FC layers.
    Lesson: depth with small filters is powerful but inefficient.
```

**When to use VGG-style:** educational baselines, transfer learning with feature extraction, or when you need deterministic layer ordering and simple debugging.

### 2.2 ResNet: Skip Connections Change Everything

```
                        ResNet-50 Block (Bottleneck)
                        ============================

     x ───────────────────┬─────────────────────────────────┐
     │                     │                                 │ (+)
     │              ┌──────▼──────┐                          │
     │              │  1×1 Conv    │ (reduce 256→64)          │
     │              │  BN + ReLU   │                          │
     │              └──────┬──────┘                          │
     │              ┌──────▼──────┐                          │
     │              │  3×3 Conv    │ (compute 64→64)          │
     │              │  BN + ReLU   │                          │
     │              └──────┬──────┘                          │
     │              ┌──────▼──────┐                          │
     │              │  1×1 Conv    │ (expand 64→256)          │
     │              │  BN          │                          │
     │              └──────┬──────┘                          │
     │                     │ F(x)                           │
     │                     ├──────────────────► (+) ◄────────┘
     │                     │                   │
     │        (if dims match skip = x;        │
     │         else 1×1 conv on skip)          │
     │                     │                   │
     │               ReLU ◄┘                  │
     │                     │                   │
     └─────────────────────┴───────────────────┘
                           │
                           ▼  output = ReLU(F(x) + x)

    ResNet Stage Layout:
    ┌─────────────────────────────────────────────────────────────┐
    │ Stage 1: 7×7 conv, 64, stride 2 → BN → ReLU → 3×3 MaxPool │
    │ Stage 2: [Bottleneck ×3]  256-d                             │
    │ Stage 3: [Bottleneck ×4]  512-d  (stride 2 on first block) │
    │ Stage 4: [Bottleneck ×6] 1024-d  (stride 2 on first block) │
    │ Stage 5: [Bottleneck ×3] 2048-d  (stride 2 on first block) │
    │ → Global Avg Pool → FC-1000                                 │
    └─────────────────────────────────────────────────────────────┘
    Total: ~25.5M params, ~4.1 GFLOPs
```

**Key architecture choices:**
- **Bottleneck** (1×1→3×3→1×1) reduces FLOPs by ~4× vs. two 3×3 convolutions at full width.
- **Stride-2 shortcut**: when spatial resolution halves, the skip path uses a strided 1×1 conv to match dimensions.
- **Pre-activation** (ResNet-v2): moving BN/ReLU before the convolutions improves very deep training (>200 layers).

### 2.3 EfficientNet: Compound Scaling

EfficientNet proposes a **compound scaling** rule that simultaneously optimizes depth, width, and resolution:

```
    depth:    d = α^φ
    width:    w = β^φ
    resolut:  r = γ^φ

    subject to: α · β² · γ² ≈ 2   (FLOPs double per step)

    φ is the user-specified compute budget multiplier.
    α, β, γ are found by small grid search on the base model.
    (Original: α=1.2, β=1.1, γ=1.15)
```

**Architecture detail (MBConv block):**

```
    MBConv Block (Mobile Inverted Bottleneck)
    ==========================================

    Input ─────────────────────────┬───────────────────┐
         │                         │                   │ (+)
    ┌────▼────┐                    │                   │
    │ 1×1 Conv│ (expand)           │                   │
    │  BN/SiLU│ w=expand_ratio     │                   │
    └────┬────┘                    │                   │
    ┌────▼────────────┐            │                   │
    │ Depthwise 3×3/5×5│ (spatial) │                   │
    │  BN/SiLU         │           │                   │
    │  SE (squeeze-exc)│           │                   │
    └────┬────────────┘            │                   │
    ┌────▼────┐                    │                   │
    │ 1×1 Conv│ (project)          │                   │
    │  BN     │ no activation      │                   │
    └────┬────┘                    │                   │
         ├────────────────────────►(+) ◄───────────────┘
         │                         │
         ▼                     (skip only when
       Output                 stride=1 & in=out ch)
```

### 2.4 MobileNet: Mobile-First Design

**MobileNetV2** introduces the inverted residual (narrow→wide→narrow) and linear bottlenecks:

- **Expansion factor** (typically 6): projects from low-dim to high-dim before depthwise conv.
- **Linear bottleneck**: final 1×1 projection has *no activation*, preserving information in low-dimensional space.
- **Trade-off**: ~3.4M params at 1.0 multiplier; scales with width/resolution multipliers.

**MobileNetV3** adds:
- **h-swish** and **h-sigmoid** activations (hardware-efficient alternatives).
- **SE blocks** in select layers (found via NAS).
- **Platform-aware NAS** (MnasNet-style) to optimize for real latency on target hardware.

### 2.5 CNN Architecture Comparison

```
    ┌───────────────────────────────────────────────────────────────────────┐
    │       CNN Architecture Trade-off Space                                │
    │                                                                       │
    │   Accuracy                                                             │
    │    (%) 97┤                                          ★ EfficientNetV2  │
    │         │                                    ★                        │
    │    96┤                          ★ ResNet-152                             │
    │       │                    ★                                             │
    │    95┤          ★ ResNet-50                                             │
    │       │                                                                │
    │    94┤   ★ VGG-16                                                     │
    │       │                                                                │
    │    93┤                                                                │
    │       │          ★ MobileNetV3                                         │
    │    92┤                                                                │
    │       │ ★ MobileNetV2                                                  │
    │    91┤                                                                │
    │       └──┬─────────┬──────────┬──────────┬──────────┬──────────►       │
    │          0.1       1          4          10         30  GFLOPs        │
    │                                                                       │
    │   ★ Pareto frontier moves right→down: cheaper models, lower accuracy │
    │   EfficientNet family dominates the Pareto frontier                   │
    └───────────────────────────────────────────────────────────────────────┘
```

---

## 3. Designing Transformers

### 3.1 Full Encoder-Decoder Transformer

```
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                    THE TRANSFORMER  (Vaswani et al., 2017)                  │
    │                                                                             │
    │  ┌─────────────────────────────┐   ┌────────────────────────────────┐      │
    │  │       DECODER STACK × N      │   │      ENCODER STACK × N        │      │
    │  │                              │   │                                │      │
    │  │  ┌───────────────────────┐  │   │  ┌──────────────────────┐     │      │
    │  │  │  Linear + Softmax     │  │   │  │  Feed-Forward        │     │      │
    │  │  │  (over vocab)         │  │   │  │  (d_model→d_ff→d_model)│    │      │
    │  │  └───────────┬───────────┘  │   │  └──────────┬───────────┘     │      │
    │  │             ▲               │   │             ▲                 │      │
    │  │  ┌──────────┴───────────┐  │   │  ┌──────────┴───────────┐     │      │
    │  │  │  Add & Norm          │  │   │  │  Add & Norm           │     │      │
    │  │  └──────────┬───────────┘  │   │  └──────────┬───────────┘     │      │
    │  │             ▲               │   │             ▲                 │      │
    │  │     ┌───────┴──────┐       │   │     ┌───────┴──────┐          │      │
    │  │     │  FFN          │       │   │     │  FFN          │          │      │
    │  │     │  (d_ff)       │       │   │     │  (d_ff)      │          │      │
    │  │     └───────┬──────┘       │   │     └───────┬──────┘          │      │
    │  │             ▲               │   │             ▲                 │      │
    │  │  ┌──────────┴───────────┐  │   │  ┌──────────┴───────────┐     │      │
    │  │  │  Add & Norm          │  │   │  │  Add & Norm           │     │      │
    │  │  └──────────┬───────────┘  │   │  └──────────┬───────────┘     │      │
    │  │             ▲               │   │             ▲                 │      │
    │  │  ┌──────────┴───────────┐  │   │  ┌──────────┴───────────┐     │      │
    │  │  │ Multi-Head Cross     │◄─┼───┼──│ Multi-Head Self       │     │      │
    │  │  │ Attention (K,V from   │  │   │  │ Attention              │     │      │
    │  │  │  encoder output)      │  │   │  │  (Q=K=V from prev    │     │      │
    │  │  └──────────┬───────────┘  │   │  │   layer output)       │     │      │
    │  │             ▲               │   │  └──────────┬───────────┘     │      │
    │  │  ┌──────────┴───────────┐  │   │             ▲                 │      │
    │  │  │  Add & Norm          │  │   │  ┌──────────┴───────────┐     │      │
    │  │  └──────────┬───────────┘  │   │  │  Add & Norm           │     │      │
    │  │             ▲               │   │  └──────────┬───────────┘     │      │
    │  │  ┌──────────┴───────────┐  │   │             ▲                 │      │
    │  │  │ Masked Multi-Head    │  │   │  ┌──────────┴───────────┐     │      │
    │  │  │ Self-Attention       │  │   │  │  Input Embedding      │     │      │
    │  │  │ (causal mask)        │  │   │  │  + Positional Enc     │     │      │
    │  │  └──────────┬───────────┘  │   │  └──────────┬───────────┘     │      │
    │  │             ▲               │   │             ▲                 │      │
    │  │  ┌──────────┴───────────┐  │   │             │                 │      │
    │  │  │  Output Embedding     │  │   │   Encoder Input               │      │
    │  │  │  + Positional Enc    │  │   │   (shifted right)             │      │
    │  │  └──────────┬───────────┘  │   │             ▲                 │      │
    │  │             ▲               │   │             │                 │      │
    │  │  Decoder Input             │   │          Encoder Input          │      │
    │  │  (shifted right)           │   │                                │      │
    │  └─────────────────────────────┘   └────────────────────────────────┘      │
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Multi-Head Attention — Internal Detail

```
    ┌───────────────────────────────────────────────────────────────────────┐
    │                    MULTI-HEAD ATTENTION — MECHANISM                    │
    │                                                                       │
    │   Input X (seq_len × d_model)                                         │
    │       │                                                               │
    │       ├───► W_Q ──► Q  (seq_len × d_k)     ┐                         │
    │       │         split into h heads          │ h heads, each           │
    │       ├───► W_K ──► K  (seq_len × d_k)     │ d_k = d_model / h      │
    │       │         split into h heads          │                         │
    │       └───► W_V ──► V  (seq_len × d_k)     ┘                         │
    │                                                                       │
    │              For each head i:                                          │
    │              ┌─────────────────────────────────────────────┐           │
    │              │                                             │           │
    │              │   Attention(Q_i, K_i, V_i)                  │           │
    │              │                                            │           │
    │              │           Q_i · K_i^T                      │           │
    │              │   A_i = ────────────────                   │           │
    │              │          √d_k                              │           │
    │              │                                            │           │
    │              │   ┌─────────────────────────────┐          │           │
    │              │   │        Softmax               │          │           │
    │              │   │    ┌───┬───┬───┬───┐        │          │           │
    │              │   │    │.1 │.7 │.1 │.1 │  ←─ row   │          │           │
    │              │   │    ├───┼───┼───┼───┤  attention│          │           │
    │              │   │    │.05│.1 │.8 │.05│    weights│          │           │
    │              │   │    ├───┼───┼───┼───┤   (mask  │          │           │
    │              │   │    │0  │0  │0  │1  │   applied)│          │           │
    │              │   │    └───┴───┴───┴───┘          │          │           │
    │              │   └─────────┬───────────────────────┘          │           │
    │              │             ▼                                  │           │
    │              │   head_i = softmax(A_i) · V_i                  │           │
    │              │         (seq_len × d_k)                        │           │
    │              └─────────────┬───────────────────────────────────┘           │
    │                            │                                           │
    │       ┌────────────────────┼────────────────────┐                      │
    │       │                    │                     │                      │
    │       head_1           head_2    ...       head_h                      │
    │       (seq×d_k)       (seq×d_k)            (seq×d_k)                  │
    │       │                  │                     │                        │
    │       └──────────────────┼─────────────────────┘                        │
    │                          │ Concat                                          │
    │                          ▼                                                 │
    │                   (seq_len × d_model)                                      │
    │                          │                                                 │
    │                     W_O projection                                         │
    │                          ▼                                                 │
    │                   Output (seq_len × d_model)                               │
    │                                                                           │
    │   Params per head: d_model×d_k (Q) + d_model×d_k (K)                     │
    │                     + d_model×d_k (V) = 3×d_model² / h                   │
    │   Total attention params: 4 × d_model² (including W_O)                   │
    │   FLOPs per layer: ~ 4 × seq_len² × d_model  (quadratic in seq!)        │
    └───────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Positional Encoding

Since attention is permutation-invariant, position information must be injected explicitly:

| Method | Formula | Properties |
|--------|---------|------------|
| Sinusoidal (original) | PE(pos,2i) = sin(pos/10000^{2i/d}); PE(pos,2i+1) = cos(...) | No learned parameters; generalizes to unseen lengths |
| Learned | Embedding table indexed by position | Flexible but doesn't generalize past training length |
| RoPE (Rotary) | Rotate Q,K vectors by angle θ=position×freq | Relative position awareness; dominant in LLMs (LLaMA, GPT-NeoX) |
| ALiBi | Add linear bias to attention scores: -m·|i-j| | No position embedding needed; length extrapolation |

**RoPE is the current default** for decoder-only LLMs — it encodes *relative* position directly in the attention computation, allowing better extrapolation to longer sequences.

### 3.4 Decoder-Only (GPT-style) vs Encoder-Only (BERT-style) vs Encoder-Decoder (T5-style)

```
    ┌────────────────────────────────────────────────────────────────────┐
    │  Three Transformer Paradigms                                       │
    │                                                                    │
    │  ENCODER-ONLY (BERT)        DECODER-ONLY (GPT)       ENC-DEC (T5) │
    │                                                                    │
    │     ┌──────────┐            ┌──────────┐        ┌──────────┐      │
    │     │[CLS] tok1│            │ tok1 tok2 │        │enc tok1  │      │
    │     │ tok2 tok3│            │ tok3 tok4 │        │enc tok2  │      │
    │     │ ...      │            │ ...      │        │ ...      │      │
    │     │ [SEP]    │            │ [EOS]    │        │          │      │
    │     └────┬─────┘            └────┬─────┘        └────┬─────┘      │
    │          │                       │                    │            │
    │   Self-Attn                Causal Self-Attn           │            │
    │   (bidirectional)         (autoregressive mask)     │            │
    │          │                       │                    │            │
    │   FFN × L                      FFN × L               │            │
    │          │                       │                    │            │
    │     ┌────▼─────┐          ┌─────▼──────┐      ┌─────▼──────┐    │
    │     │Pool/CLS  │          │LM Head     │      │ Cross-Attn │    │
    │     │head      │          │(next token)│      │ (K,V ← enc) │   │
    │     └────┬─────┘          └─────┬──────┘      │ + Causal    │    │
    │          │                       │             │ Self-Attn   │    │
    │   Task head (NLI,QA)       Autoregressive     │ FFN × L     │    │
    │                          generation loop       └──────┬─────┘    │
    │                                               │            │
    │   Use: Classification,     Use: Generation,    Decoder head  │
    │   NER, extraction         chat, code          │              │
    │                                                ▼              │
    │                                          Use: Translation,   │
    │                                          summarization       │
    └────────────────────────────────────────────────────────────────────┘
```

**Design decision tree:**
- Need双向 context + classification/NER → **Encoder-only (BERT/DeBERTa)**
- Need autoregressive generation → **Decoder-only (GPT/LLaMA)**
- Need input-conditioned generation (translation, summarization) → **Encoder-decoder (T5/BART)** or **decoder-only with prompted input**
- Modern trend: decoder-only for everything, but encoder-decoder can be more parameter-efficient for seq2seq.

---

## 4. Hybrid Architectures

### 4.1 CNN + Transformer

```
    ┌──────────────────────────────────────────────────────────────────┐
    │  Hybrid CNN+Transformer (e.g., ViT with Conv Stem)             │
    │                                                                  │
    │  Input Image (224×224×3)                                        │
    │       │                                                          │
    │  ┌────▼────────────────────────────────────────────────────┐    │
    │  │  Conv Stem: 2-3 conv layers (3×3, stride 2)            │    │
    │  │  Purpose: extract local features, reduce resolution     │    │
    │  │  Output: 56×56×64 (or similar)                          │    │
    │  └────┬────────────────────────────────────────────────────┘    │
    │       │                                                          │
    │  ┌────▼────────────────────────────────────────────────────┐    │
    │  │  Patch Embedding: Conv 16×16 stride 16                   │    │
    │  │  OR overlapping patches via conv stem                     │    │
    │  │  Output: 196 tokens × d_model                              │    │
    │  └────┬────────────────────────────────────────────────────┘    │
    │       │                                                          │
    │  ┌────▼────────────────────────────────────────────────────┐    │
    │  │  + Positional Embedding (Learned or 2D sinusoidal)      │    │
    │  └────┬────────────────────────────────────────────────────┘    │
    │       │                                                          │
    │  ┌────▼────────────────────────────────────────────────────┐    │
    │  │  Transformer Encoder × L                                 │    │
    │  │  (Self-Attn → Add&Norm → FFN → Add&Norm) × L           │    │
    │  └────┬────────────────────────────────────────────────────┘    │
    │       │                                                          │
    │  ┌────▼────────────────────────────────────────────────────┐    │
    │  │  Classification Head: [CLS] token → Linear → Classes    │    │
    │  │  OR Dense Prediction Head: reshape tokens → conv → out │    │
    │  └──────────────────────────────────────────────────────────┘    │
    │                                                                  │
    │  Why hybrid?                                                     │
    │  • Conv stem = stable training, better data efficiency           │
    │  • Transformer = global context, scaling behavior                │
    │  • Best of both: local归纳偏置 + global reasoning                │
    └──────────────────────────────────────────────────────────────────┘
```

**Notable hybrid designs:**
- **CoAtNet**: interleaves conv and attention blocks in stages; uses relative attention.
- **ConvNeXt**: modernizes ResNet with Transformer-inspired changes (GELU, LayerNorm, larger kernels, inverted bottleneck) — achieves ViT-level accuracy without attention.
- **CvT**: Convolutional Vision Transformer — conv projections in each stage before attention, progressive downsampling.
- **LeViT**: Fast inference hybrid with attention bias and patched distillation.

### 4.2 RNN + Attention

Used in sequence-to-sequence models before Transformers dominated; still relevant for streaming/online tasks:

```
    ┌──────────────────────────────────────────────────────────────┐
    │  BiRNN Encoder + Attention Decoder (Bahdanau-style)        │
    │                                                              │
    │  Encoder:                                                    │
    │  ┌───┐ ┌───┐ ┌───┐ ┌───┐                                  │
    │  │ → │→│ → │→│ → │→│ → │   Forward LSTM                    │
    │  └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘                                  │
    │    │     │     │     │   h_t = [→h_t; ←h_t]               │
    │  ┌─┴─┐ ┌─┴─┐ ┌─┴─┐ ┌─┴─┐                                  │
    │  │ ← │←│ ← │←│ ← │←│ ← │   Backward LSTM                   │
    │  └───┘ └───┘ └───┘ └───┘                                    │
    │    │     │     │     │                                       │
    │    ▼     ▼     ▼     ▼  encoder outputs                      │
    │                                                              │
    │  Decoder (at each step t):                                   │
    │    1. Compute attention: α_t = softmax(score(s_{t-1}, h_i))  │
    │    2. Context vector: c_t = Σ α_t,i · h_i                   │
    │    3. Decoder input: concat(embed(y_{t-1}), c_t)             │
    │    4. Decoder LSTM step → s_t                                │
    │    5. Output: softmax(W · concat(s_t, c_t))                  │
    └──────────────────────────────────────────────────────────────┘
```

### 4.3 State-Space Models (SSMs) — The New Hybrid

**Mamba / S4** replace attention with structured state spaces — O(n) instead of O(n²):

- **Selection mechanism** (Mamba): input-dependent state transitions allow content-based filtering.
- **Scan operation**: parallelizable during training, recurrent during inference.
- **Tradeoff**:loses the full global connectivity of attention but gains linear scaling and fast autoregressive inference.

---

## 5. Neural Architecture Search

### 5.1 NAS Pipeline

```
    ┌──────────────────────────────────────────────────────────────────────┐
    │                NEURAL ARCHITECTURE SEARCH PIPELINE                    │
    │                                                                      │
    │  ┌──────────────┐     ┌──────────────┐     ┌──────────────────┐    │
    │  │  SEARCH SPACE │────►│  SEARCH       │────►│  EVALUATE        │    │
    │  │  DEFINITION   │     │  STRATEGY     │     │  (TRAIN & TEST)  │    │
    │  │              │     │              │     │                  │    │
    │  │ • Cell types │     │ • RL         │     │ • Full training  │    │
    │  │ • Connections│     │ • Evolution   │     │ • Proxy tasks   │    │
    │  │ • Ops per    │     │ • Gradient   │     │ • Weight sharing │    │
    │  │   edge       │     │   (DARTS)    │     │   (Supernet)    │    │
    │  │ • Constraints│     │ • Random     │     │ • Early stopping │    │
    │  └──────────────┘     └──────┬───────┘     └────────┬─────────┘    │
    │                              │                       │              │
    │                              └───────────┬───────────┘              │
    │                                          │                          │
    │                                    ┌─────▼──────┐                 │
    │                                    │  ARCHITECTURE│                │
    │                                    │  CANDIDATE   │                │
    │                                    └─────┬──────┘                 │
    │                                          │                          │
    │                              ┌───────────┴───────────┐             │
    │                              │  FEEDBACK LOOP         │             │
    │                              │  (reward / accuracy /  │             │
    │                              │   latency / energy)    │             │
    │                              └──────────────────────┘             │
    └──────────────────────────────────────────────────────────────────────┘
```

### 5.2 DARTS (Differentiable Architecture Search)

DARTS relaxes the discrete search space into a continuous one:

```
    ┌──────────────────────────────────────────────────────────────────────┐
    │  DARTS: Differentiable Architecture Search                           │
    │                                                                      │
    │  Discrete: choose one operation per edge                             │
    │    o(i,j) = argmax_k α_{i,j,k} · op_k(x)                           │
    │                                                                      │
    │  Continuous relaxation:                                              │
    │    ō(i,j) = Σ_k  softmax(α_{i,j,k}) · op_k(x)                     │
    │                                                                      │
    │    where α_{i,j,k} are learnable architecture parameters             │
    │                                                                      │
    │  ┌─────────────────────────────────────────────────────────┐         │
    │  │  Cell Search (Normal Cell)                               │         │
    │  │                                                          │         │
    │  │  Input Node 0 ──►┬─────────────────────┬──────────► Node 2    │         │
    │  │                  │ softmix over ops     │                    │         │
    │  │  Input Node 1 ──►┼──► [max_pool]  ─0.1─┤                    │         │
    │  │                  │──► [avg_pool]  ─0.2──┤                    │         │
    │  │                  │──► [skip_connect]─0.6┤─► argmax ──► pick   │         │
    │  │                  │──► [conv_3x3]  ─0.05┤    (after search)  │         │
    │  │                  │──► [conv_5x5]  ─0.03┤                    │         │
    │  │                  │──► [dil_conv]  ─0.02┤                    │         │
    │  │                  └─────────────────────┘                    │         │
    │  └─────────────────────────────────────────────────────────┘         │
    │                                                                      │
    │  Training: bi-level optimization                                    │
    │    outer: minimize L_val w.r.t. α (architecture)                    │
    │    inner: minimize L_train w.r.t. w (weights)                        │
    │                                                                      │
    │  Discretization: after search, keep top-2 ops per node               │
    │  Total search cost: ~0.5-4 GPU-days (vs. 2000+ GPU-days for RL-NAS) │
    └──────────────────────────────────────────────────────────────────────┘
```

**Known issues with DARTS:**
- **Discretization gap**: soft mixture performance ≠ single-operation performance.
- **Skip-connect dominance**: can cause unstable shallow networks.
- **Mitigations**: DARTS-, P-DARTS, PC-DARTS, DrNAS all address stability.

### 5.3 Efficient Search Strategies

| Method | Search Cost | Strategy | Pros | Cons |
|--------|------------|----------|------|------|
| **Random search** | 0 | Sample randomly | Strong baseline, no optimization | Suboptimal |
| **Evolution** | 10-100 GPU-days | Mutation + selection | Flexible, multi-objective | Slow, needs many evaluations |
| **RL** (NASNet) | 2000+ GPU-days | Policy gradient | Can find novel patterns | Extremely expensive |
| **DARTS** | 0.5-4 GPU-days | Gradient-based | Fast, differentiable | Discretization gap |
| **One-shot** | 1-5 GPU-days | Supernet + sampling | Efficient, scalable | Requires good supernet design |
| **ProxylessNAS** | 0.2-1 GPU-days | Path-level binarization | Hardware-aware | Complex implementation |

---

## 6. Scaling Laws & Compute-Optimal Models

### 6.1 Chinchilla Scaling Laws

The foundational result (Hoffmann et al., 2022): for compute-optimal training, **model size and data size should scale proportionally**.

```
    ┌──────────────────────────────────────────────────────────────────────┐
    │           CHINCHILLA SCALING LAWS                                    │
    │                                                                      │
    │   Loss(C) ≈ A·N^{-α} + B·D^{-β} + E                               │
    │                                                                      │
    │   N = # parameters, D = # tokens, C = compute budget                 │
    │   α ≈ 0.34, β ≈ 0.28, E ≈ 1.69 (irreducible loss)                │
    │                                                                      │
    │   Key insight: optimal N ∝ C^{0.5}, D ∝ C^{0.5}                    │
    │                                                                      │
    │   BEFORE Chinchilla:                                                 │
    │   ┌────────────────────────────────────────────────────────────┐    │
    │   │  GPT-3:  175B params, 300B tokens  (UNDER-TRAINED)        │    │
    │   │  Gopher: 280B params, 300B tokens  (UNDER-TRAINED)        │    │
    │   │  → assumption: triple params, keep data fixed               │    │
    │   └────────────────────────────────────────────────────────────┘    │
    │                                                                      │
    │   AFTER Chinchilla:                                                  │
    │   ┌────────────────────────────────────────────────────────────┐    │
    │   │  Chinchilla: 70B params, 1.4T tokens  (COMPUTE-OPTIMAL)   │    │
    │   │  → same compute as Gopher, better performance              │    │
    │   │  → trained on ~20× more data relative to parameter count   │    │
    │   └────────────────────────────────────────────────────────────┘    │
    │                                                                      │
    │   Optimal model size for given compute:                             │
    │                                                                      │
    │   Compute (FLOPs)  │  Optimal N  │  Optimal D (tokens)             │
    │   ─────────────────┼────────────┼────────────────────               │
    │   1e18             │  400M      │  8B                               │
    │   1e19             │  1.8B      │  37B                              │
    │   1e20             │  8B        │  170B                             │
    │   1e21             │  39B       │  790B                             │
    │   1e22             │  180B      │  3.7T                             │
    │                                                                      │
    │   Rule of thumb: ~20 tokens per parameter at Chinchilla optimal     │
    └──────────────────────────────────────────────────────────────────────┘
```

### 6.2 Scaling Comparison Diagram

```
    ┌──────────────────────────────────────────────────────────────────────┐
    │  Model Size vs. Performance — Compute-Optimal Frontier              │
    │                                                                      │
    │  Loss                                                                  │
    │  (↓ better)                                                          │
    │  4.0 ┤                          ╭────────── Chinchilla optimal       │
    │      │                    ╭─────╯                                    │
    │  3.5 ┤              ╭─────╯                             ╭── LLM     │
    │      │        ╭─────╯              ╭─────────────────╯   scaling   │
    │  3.0 ┤  ╭─────╯              ╭─────╯                     curve      │
    │      │──╯              ╭─────╯                                      │
    │  2.5 ┤           ╭─────╯                                           │
    │      │     ╭─────╯                                                 │
    │  2.0 ┤╭─────╯                                                       │
    │      ││                                                               │
    │  1.7 ┤├─── irreducible loss (E ≈ 1.69)                              │
    │      └──┬─────────┬──────────┬──────────┬──────────┬──►               │
    │        10M       100M       1B        10B       100B   Params        │
    │                                                                      │
    │                                                                      │
    │   For a FIXED compute budget C, three regimes:                      │
    │                                                                      │
    │   ┌─────────────────┬──────────────────────────────────────────┐    │
    │   │  UNDERTRAINED   │  Too large model, not enough data        │    │
    │   │                 │  (GPT-3 regime: 175B/300B tokens)         │    │
    │   ├─────────────────┼──────────────────────────────────────────┤    │
    │   │  OPTIMAL         │  Balanced N ∝ C^0.5, D ∝ C^0.5        │    │
    │   │                 │  (Chinchilla regime: 70B/1.4T tokens)     │    │
    │   ├─────────────────┼──────────────────────────────────────────┤    │
    │   │  OVERTRAINED     │  Too small model, excess data           │    │
    │   │                 │  (Emergent only when compute >> this)     │    │
    │   └─────────────────┴──────────────────────────────────────────┘    │
    └──────────────────────────────────────────────────────────────────────┘
```

### 6.3 Beyond Chinchilla

- **Llama 3**: trained on 15T tokens with 8B/70B/405B models — well beyond the Chinchilla ratio (over-training). The insight: inference cost matters more than training cost in deployment; smaller over-trained models are cheaper to serve.
- **Over-training ratio**: practical models often use 50-200× tokens per parameter rather than the Chinchilla-optimal ~20×, because Serving cost savings >>> extra training cost.
- **Data-constrained scaling**: when data is limited, epochs (>1 pass over data) are acceptable with careful regularization (weight decay, dropout, data augmentation).

---

## 7. Memory & Compute Optimization

### 7.1 Gradient Checkpointing (Activation Recomputation)

```
    ┌──────────────────────────────────────────────────────────────────┐
    │                    GRADIENT CHECKPOINTING                        │
    │                                                                  │
    │  Standard (save all activations):                               │
    │  ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐           │
    │  │ L1 │→│ L2 │→│ L3 │→│ L4 │→│ L5 │→│ L6 │→│ L7 │→│ L8 │           │
    │  └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘           │
    │    │     │     │     │     │     │     │     │              │
    │    ▼     ▼     ▼     ▼     ▼     ▼     ▼     ▼  ALL stored  │
    │    Memory: O(N) activations                                   │
    │                                                                  │
    │  Checkpointed (save selected, recompute rest):                   │
    │  ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐           │
    │  │ L1 │→│ L2 │→│ L3 │→│ L4 │→│ L5 │→│ L6 │→│ L7 │→│ L8 │           │
    │  └─┬─┘   └─┬─┘   └─┬─┘   └─┬─┘   └─┬─┘   └─┬─┘   └─┬─┘           │
    │    ▼       ✗       ✗       ▼       ✗       ✗       ✗       ▼       │
    │  CKPT   discard  discard  CKPT   discard  discard discard  CKPT  │
    │                                                                  │
    │  Backward pass: recompute from nearest checkpoint               │
    │    L8 grad → recompute L7→L8 (from L6) → grad L6               │
    │              recompute L5→L6 (from L4) → grad L4               │
    │              ...                                                  │
    │                                                                  │
    │  Memory: O(√N) with √N checkpoints                              │
    │  Compute: +33% extra forward passes (trade memory for time)     │
    └──────────────────────────────────────────────────────────────────┘
```

### 7.2 Mixed Precision Training

```
    ┌──────────────────────────────────────────────────────────────────┐
    │                MIXED PRECISION (FP16/BF16 + FP32)                 │
    │                                                                  │
    │    ┌─────────────────────────────────────────────────────┐       │
    │    │           FP32 Master Copy of Weights              │       │
    │    │  W_fp32 = W_fp32 - lr · (ΔW cast to FP32)          │       │
    │    └────────────────────┬────────────────────────────────┘       │
    │                         │ cast to FP16/BF16                     │
    │                         ▼                                       │
    │    ┌─────────────────────────────────────────────────────┐       │
    │    │  Forward Pass in FP16/BF16                          │       │
    │    │  - Activations stored in FP16/BF16                  │       │
    │    │  - Computations: matmul, conv in FP16/BF16          │       │
    │    │  - √2× throughput on Tensor Cores                   │       │
    │    └────────────────────┬────────────────────────────────┘       │
    │                         │                                       │
    │                         ▼                                       │
    │    ┌─────────────────────────────────────────────────────┐       │
    │    │  Loss Scaling                                       │       │
    │    │  loss_scaled = loss × scale  (prevent underflow)    │       │
    │    │  scale adjusted dynamically (32768 → 1 range)       │       │
    │    └────────────────────┬────────────────────────────────┘       │
    │                         │                                       │
    │                         ▼                                       │
    │    ┌─────────────────────────────────────────────────────┐       │
    │    │  Backward Pass in FP16/BF16                         │       │
    │    │  - Gradients in FP16/BF16                            │       │
    │    │  - Grad descale: grad_real = grad_scaled / scale     │       │
    │    └────────────────────┬────────────────────────────────┘       │
    │                         │                                       │
    │                         ▼                                       │
    │    ┌─────────────────────────────────────────────────────┐       │
    │    │  FP32 Weight Update                                 │       │
    │    │  W_fp32 = W_fp32 - lr · grad_fp32                   │       │
    │    │  (accumulate in FP32 for stability)                 │       │
    │    └─────────────────────────────────────────────────────┘       │
    │                                                                  │
    │  Memory savings: ~50% reduction in activation & weight memory   │
    │  Speed: 1.5-3× on NVIDIA GPUs with Tensor Cores                │
    │  BF16 (bfloat16): no loss scaling needed; same exponent as FP32 │
    └──────────────────────────────────────────────────────────────────┘
```

### 7.3 Model Parallelism

```
    ┌──────────────────────────────────────────────────────────────────────┐
    │                  PARALLELISM STRATEGIES                                │
    │                                                                        │
    │  1. TENSOR (INTRA-LAYER) PARALLELISM                                  │
    │     Split each matmul across GPUs:                                     │
    │                                                                        │
    │     GPU 0: W₁·x    ║                                                  │
    │                   ║──► concat ──► output                               │
    │     GPU 1: W₂·x    ║                                                  │
    │     (Megatron-LM style: column-parallel then row-parallel)             │
    │     Communication: 1 all-reduce per layer forward + backward            │
    │                                                                        │
    │  2. PIPELINE (INTER-LAYER) PARALLELISM                                 │
    │     Assign consecutive layers to different GPUs:                       │
    │                                                                        │
    │     GPU 0     GPU 1     GPU 2     GPU 3                                │
    │     L1-L6     L7-L12    L13-L18   L19-L24                              │
    │     (micro-batches pipelined to hide bubble)                           │
    │     Bubble overhead: (p-1)/(p+m-1) where p=#stages, m=#microbatches  │
    │                                                                        │
    │  3. DATA PARALLELISM                                                   │
    │     Each GPU holds full model; different data batches                  │
    │     → Gradient all-reduce after each step                              │
    │     Memory: full model per GPU (doesn't help with large models)        │
    │                                                                        │
    │  4. SEQUENCE/PREFIX PARALLELISM                                        │
    │     Split long sequences across GPUs along the token dimension         │
    │     → Ring attention / DeepSpeed Ulysses                               │
    │                                                                        │
    │  5. FSDP (Fully Sharded Data Parallelism)                              │
    │     Shard parameters, grads, and optimizer state across GPUs           │
    │     Gather before compute, shard after                                 │
    │     Communication: 2 all-gathers per layer (forward+backward)           │
    │     → Best memory/speed tradeoff for most workloads                    │
    │                                                                        │
    │  ┌──────────────────────────────────────────────────────────────┐     │
    │  │  Strategy Selection Decision Tree                           │     │
    │  │                                                              │     │
    │  │  Model fits on 1 GPU?                                        │     │
    │  │    YES → Data parallelism (DDP)                             │     │
    │  │    NO  → Model fits on 1 GPU with activation offload?       │     │
    │  │            YES → FSDP (ZeRO-3)                              │     │
    │  │            NO  → Tensor parallelism + Pipeline parallelism  │     │
    │  │                  + FSDP for remaining sharding             │     │
    │  └──────────────────────────────────────────────────────────────┘     │
    └──────────────────────────────────────────────────────────────────────┘
```

### 7.4 Memory Budget Breakdown

For a transformer with *N* parameters, using Adam optimizer in mixed precision:

| Component | Memory | Formula |
|-----------|--------|---------|
| Weights (FP16) | 2N | 2 bytes × N |
| Weights (FP32 master) | 4N | 4 bytes × N |
| Gradients (FP16) | 2N | From backward pass |
| Optimizer states | 8N | m (FP32) + v (FP32) = 8N |
| Activations | Variable | ~O(N × L × seq_len / ckpt_depth) |
| **Total (approx)** | **~16-20N** | Without checkpointing, can be 20N+ |

Example: 7B parameter model → ~112-140 GB just for model + optimizer. With FSDP ZeRO-3 across 8 GPUs → ~14-18 GB per GPU.

---

## 8. Architecture Visualization & Documentation

### 8.1 Generic Architecture Design Workflow

```
    ┌──────────────────────────────────────────────────────────────────────┐
    │          NEURAL ARCHITECTURE DESIGN WORKFLOW                        │
    │                                                                      │
    │  ┌────────────────┐                                                 │
    │  │ 1. DEFINE TASK │                                                 │
    │  │ • Input/output │                                                 │
    │  │ • Metrics       │                                                 │
    │  │ • Constraints   │                                                 │
    │  └───────┬────────┘                                                 │
    │          │                                                            │
    │          ▼                                                            │
    │  ┌────────────────┐    ┌─────────────────────────────────────┐      │
    │  │ 2. SELECT BASE  │    │ Decision tree:                       │      │
    │  │    ARCHITECTURE │    │ • Image → CNN / ViT                 │      │
    │  │                │    │ • Text → Transformer                 │      │
    │  │                │    │ • Seq2Seq → Enc-Dec / Decoder-only   │      │
    │  │                │    │ • Tabular → MLP / Transformer        │      │
    │  │                │    │ • Multi-modal → Hybrid              │      │
    │  └───────┬────────┘    └─────────────────────────────────────┘      │
    │          │                                                            │
    │          ▼                                                            │
    │  ┌────────────────┐    ┌─────────────────────────────────────┐      │
    │  │ 3. CONFIGURE   │    │ Hyperparameters:                     │      │
    │  │    DESIGN SPACE │    │ • Depth / Width / Attention heads   │      │
    │  │                │    │ • Activation / Normalization         │      │
    │  │                │    │ • Dropout / Stochastic depth        │      │
    │  │                │    │ • Initializer / LR schedule          │      │
    │  └───────┬────────┘    └─────────────────────────────────────┘      │
    │          │                                                            │
    │          ▼                                                            │
    │  ┌────────────────┐    ┌─────────────────────────────────────┐      │
    │  │ 4. COMPUTE      │    │ FLOPs = 2 × Σ(params×fwd_ops)      │      │
    │  │    BUDGET CHECK │    │ Memory ≈ 16-20N + activations      │      │
    │  │                │    │ Throughput ≈ FLOPs / (GPU·TFLOPS)    │      │
    │  └───────┬────────┘    └─────────────────────────────────────┘      │
    │          │                                                            │
    │          ▼                                                            │
    │  ┌────────────────┐                                                 │
    │  │ 5. PROTOTYPE   │──► Train for 1-5 epochs on small data          │
    │  │    & SANITY    │─► Verify: loss decreases, no NaN, right shape    │
    │  └───────┬────────┘                                                 │
    │          │                                                            │
    │          ▼                                                            │
    │  ┌────────────────┐    ┌─────────────────────────────────────┐      │
    │  │ 6. SCALE UP    │    │ Apply Chinchilla-style scaling:      │      │
    │  │    & TUNE       │    │ Compute-optimal: ~20 tokens/param  │      │
    │  │                │    │ Over-train: 50-200 tokens/param      │      │
    │  │                │    │ if inference cost matters            │      │
    │  │                │    │ Tune: LR, batch size, dropout       │      │
    │  └───────┬────────┘    └─────────────────────────────────────┘      │
    │          │                                                            │
    │          ▼                                                            │
    │  ┌────────────────┐                                                 │
    │  │ 7. DOCUMENT    │─► Architecture diagram (ASCII / draw.io)       │
    │  │    & VERSION    │─► Config YAML / JSON                           │
    │  │                │─► Training recipe (optimizer, LR, schedule)    │
    │  │                │─► Benchmarks (latency, throughput, accuracy)  │
    │  └────────────────┘                                                 │
    └──────────────────────────────────────────────────────────────────────┘
```

### 8.2 Documenting an Architecture

A well-documented architecture specification should include:

```yaml
# architecture_config.yaml — Example for a custom vision transformer
model:
  name: "ViT-S/16-Custom"
  type: "encoder_only"
  input: {shape: [224, 224, 3], type: "uint8"}
  output: {dim: 1000, type: "logits"}

architecture:
  patch_size: 16
  embed_dim: 384
  depth: 12
  num_heads: 6
  mlp_ratio: 4.0
  dropout: 0.0
  attention_dropout: 0.0
  stochastic_depth: 0.1
  activation: "gelu"
  normalization: "layernorm"
  normalization_epsilon: 1e-6
  position_embedding: "learned"
  pool: "cls_token"
  conv_stem:  # optional hybrid conv prefix
    enabled: true
    layers: 3
    channels: [64, 128, 256]
    kernel_sizes: [3, 3, 3]
    strides: [2, 2, 2]

training:
  optimizer: "adamw"
  lr: 1e-3
  weight_decay: 0.05
  scheduler: "cosine"
  warmup_epochs: 5
  total_epochs: 300
  batch_size: 1024
  mixed_precision: "bf16"
  gradient_checkpointing: true
  data_resolution: 224

compute:
  parameters: 22_051_712
  FLOPs_per_image: 4_586_855_424  # 4.6 GFLOPs
  activation_memory_per_image: 8_841_216  # in elements
  inference_latency_ms: {a100: 1.2, t4: 3.8}
```

### 8.3 Architecture Visualization Checklist

Every architecture document should contain:

1. **Overall topology diagram** — which blocks connect to which, data flow direction.
2. **Block-level detail** — internals of each repeated block (residual formatting, normalization placement).
3. **Dimension annotations** — shapes at every stage transition (H, W, C for CNNs; seq_len, d_model for Transformers).
4. **Parameter count table** — per-module breakdown showing where the parameters live.
5. **FLOPs table** — per-module compute cost.
6. **Memory budget** — peak memory during training with a given batch size.
7. **Scaling notes** — how to scale depth/width/resolution, what breaks at what scale.
8. **Training recipe** — optimizer, LR schedule, batch size, and any stabilization tricks (warmup, grad clipping, etc.).

### 8.4 Tools for Architecture Documentation

| Tool | Use | Output |
|------|-----|--------|
| `torchinfo` / `torchsumary` | Auto-generate layer table | Text table with params/FLOPs |
| `Netron` | Visualize ONNX/PyTorch graphs | Interactive web view |
| `draw.io` / `excalidraw` | Manual architecture diagrams | SVG/PNG |
| `tikz` / `plotneuralnet` | LaTeX neural network diagrams | PDF |
| ASCII art (this doc) | Version-control-friendly diagrams | Markdown |
| `wandb` / `tensorboard` | Training metric tracking | Web dashboard |

---

## Appendix: Quick Reference — Architecture Design Decision Matrix

```
    ┌──────────────────┬──────────────────────────────────────────────────────┐
    │  Decision Point   │  Recommendation                                     │
    ├──────────────────┼──────────────────────────────────────────────────────┤
    │  CNN activation   │  ReLU (fast), Swish (quality), ReLU6 (quantized)   │
    │  Transformer act  │  GELU (classic), SwiGLU (LLaMA-family)             │
    │  Normalization    │  BN for CNNs, LN/RMSNorm for Transformers           │
    │  Normalizer place │  Pre-norm (stable), Post-norm (slightly better)    │
    │  Initial weights  │  He for ReLU, Xavier for tanh, tent for deep nets  │
    │  Skip connections │  Always (ResNet-style). Period.                     │
    │  Positional enc  │  RoPE for LLMs, Learned for ViTs, ALiBi for extrap │
    │  Attention type   │  Flash-2 (training), KV-cache (inference)          │
    │  Embedding concat │  Patch embedding for images, token embedding for text│
    │  Depth vs width   │  Depth for accuracy, width for parallelism + speed│
    │  Scaling strategy │  Compound (EfficientNet) or just depth (GPT-style) │
    │  Over-training    │  Yes — 50-200× tokens/param for better inference    │
    │  Precision        │  BF16 mixed for training, FP16/INT8 for inference  │
    │  Parallelism      │  FSDP first, tensor+pipeline only if needed        │
    │  Checkpointing    │  Enable for >1B models, ~33% compute overhead       │
    └──────────────────┴──────────────────────────────────────────────────────┘
```

---

*This document is part of the Deep Researcher Architecture Series. For implementation details, see the corresponding code modules in the `agentic_AI/` codebase.*

---

## Real References

### CNN Design & Classic Architectures

1. Simonyan, K., Zisserman, A., "Very Deep Convolutional Networks for Large-Scale Image Recognition," *ICLR 2015*, arXiv:1409.1556.  
2. He, K., Zhang, X., Ren, S., Sun, J., "Deep Residual Learning for Image Recognition," *CVPR 2016*, arXiv:1512.03385.  
3. He, K., Zhang, X., Ren, S., Sun, J., "Identity Mappings in Deep Residual Networks," *ECCV 2016*, arXiv:1603.05027.  
4. Huang, G., Liu, Z., Van Der Maaten, L., Weinberger, K.Q., "Densely Connected Convolutional Networks," *CVPR 2017*, arXiv:1608.06993.  
5. Szegedy, C., Liu, W., Jia, Y., Sermanet, P., Reed, S., Anguelov, D., Erhan, D., Vanhoucke, V., Rabinovich, A., "Going Deeper with Convolutions," *CVPR 2015*, arXiv:1409.4842.

### Efficient CNN Architectures

6. Howard, A.G., Zhu, M., Chen, B., Kalenichenko, D., Wang, W., Weyand, T., Andreetto, M., Adam, H., "MobileNets: Efficient Convolutional Neural Networks for Mobile Vision Applications," *arXiv 2017*, arXiv:1704.04861.  
7. Sandler, M., Howard, A., Zhu, M., Zhmoginov, A., Chen, L.-C., "MobileNetV2: Inverted Residuals and Linear Bottlenecks," *CVPR 2018*, arXiv:1801.04381.  
8. Howard, A., Sandler, M., Chu, B., Chen, L.-C., Wang, B., Tan, M., et al., "Searching for MobileNetV3," *ICCV 2019*, arXiv:1905.02244.  
9. Zhang, X., Zhou, X., Lin, M., Sun, J., "ShuffleNet: An Extremely Efficient Convolutional Neural Network for Mobile Devices," *CVPR 2018*, arXiv:1707.01083.  
10. Tan, M., Le, Q.V., "EfficientNet: Rethinking Model Scaling for Convolutional Neural Networks," *ICML 2019*, arXiv:1905.11946.  
11. Tan, M., Le, Q.V., "EfficientNetV2: Smaller Models, Faster Training," *ICML 2021*, arXiv:2104.00298.

### Vision Transformers & Hybrid Architectures

12. Dosovitskiy, A., Beyer, L., Kolesnikov, A., Weissenborn, D., Zhai, X., Unterthiner, T., Dehghani, M., et al., "An Image Is Worth 16x16 Words: Transformers for Image Recognition at Scale," *ICLR 2021*, arXiv:2010.11929.  
13. Liu, Z., Lin, Y., Cao, Y., Hu, H., Wei, Y., Zhang, Z., Lin, S., Guo, B., "Swin Transformer: Hierarchical Vision Transformer Using Shifted Windows," *ICCV 2021*, arXiv:2103.14030.  
14. Dai, Z., Liu, H., Le, Q.V., Tan, M., "CoAtNet: Marrying Convolution and Attention for All Data Sizes," *NeurIPS 2021*, arXiv:2106.04803.  
15. Liu, Z., Mao, H., Wu, C.-Y., Feichtenhofer, C., Darrell, T., Xie, S., "A ConvNet for the 2020s," *CVPR 2022*, arXiv:2201.03545.  
16. Wu, H., Xiao, B., Codella, N., Liu, M., Dai, Z., Yuan, L., Zhang, L., "CvT: Introducing Convolutions to Vision Transformers," *ICCV 2021*, arXiv:2103.15808.  
17. Graham, B., Elsen, E., Goodfellow, I., "LeViT: A Vision Transformer in Conventional Form for Deployment," *ICCV 2021*, arXiv:2104.01136.

### Transformer Architecture & Attention

18. Vaswani, A., Shazeer, N., Parmar, N., Uszkoreit, J., Jones, L., Gomez, A.N., Kaiser, L., Polosukhin, I., "Attention Is All You Need," *NeurIPS 2017*, arXiv:1706.03762.  
19. Devlin, J., Chang, M.-W., Lee, K., Toutanova, K., "BERT: Pre-training of Deep Bidirectional Transformers for Language Understanding," *NAACL-HLT 2019*, arXiv:1810.04805.  
20. Radford, A., Wu, J., Child, R., Luan, D., Amodei, D., Sutskever, I., "Language Models are Unsupervised Multitask Learners," *OpenAI Technical Report 2019*.  
21. Raffel, C., Shazeer, N., Roberts, A., Lee, K., Narang, S., Matena, M., Zhou, Y., Li, W., Liu, P.J., "Exploring the Limits of Transfer Learning with a Unified Text-to-Text Transformer," *JMLR 2020*, arXiv:1910.10683.  
22. Su, J., Ahmed, M., Lu, Y., Pan, S., Bo, W., Liu, K., "RoFormer: Enhanced Transformer with Rotary Position Embedding," *Neurocomputing 2024*, arXiv:2104.09864.  
23. Ofir, O., Press, O., Smith, N.A., "Short Universal Context Orderings Are Better Than ALiBi for Length Extrapolation," *arXiv 2024*, arXiv:2407.01800. See also Press, O., Smith, N.A., Lewis, M., "Train Short, Test Long: Attention with Linear Biases Enables Input Length Extrapolation," *ICLR 2022*, arXiv:2108.12409.

### Positional Encoding & Normalization

24. Shaw, P., Uszkoreit, J., Vaswani, A., "Self-Attention with Relative Position Representations," *NAACL-HLT 2018*, arXiv:1803.02155.  
25. Zhang, B., Sennrich, R., "Root Mean Square Layer Normalization," *NeurIPS 2019*, arXiv:1910.07467.  
26. Ioffe, S., Szegedy, C., "Batch Normalization: Accelerating Deep Network Training by Reducing Internal Covariate Shift," *ICML 2015*, arXiv:1502.03167.  
27. Ba, J.L., Kiros, J.R., Hinton, G.E., "Layer Normalization," *arXiv 2016*, arXiv:1607.06450.  
28. Wu, Y., He, K., "Group Normalization," *ECCV 2018*, arXiv:1803.08494.

### Activation Functions

29. Nair, V., Hinton, G.E., "Rectified Linear Units Improve Restricted Boltzmann Machines," *ICML 2010*.  
30. Hendrycks, D., Gimpel, K., "Gaussian Error Linear Units (GELUs)," *arXiv 2016*, arXiv:1606.08415.  
31. Ramachandran, P., Zoph, B., Le, Q.V., "Searching for Activation Functions," *arXiv 2017*, arXiv:1710.05941. (Swish/SiLU)  
32. Misra, D., "Mish: A Self Regularized Non-Monotonic Activation Function," *BMVC 2020*, arXiv:1908.08681.  
33. Shazeer, N., "GLU Variants Improve Transformer," *arXiv 2020*, arXiv:2002.05202.

### Neural Architecture Search (NAS)

34. Zoph, B., Le, Q.V., "Neural Architecture Search with Reinforcement Learning," *ICLR 2017*, arXiv:1611.01578.  
35. Zoph, B., Vasudevan, V., Shlens, J., Le, Q.V., "Learning Transferable Architectures for Scalable Image Recognition," *CVPR 2018*, arXiv:1707.07012.  
36. Liu, H., Simonyan, K., Yang, Y., "DARTS: Differentiable Architecture Search," *ICLR 2019*, arXiv:1806.09055.  
37. Chen, X., Xie, L., Wu, J., Tian, Q., "Progressive Differentiable Architecture Search: Bridging the Depth Gap Between Search and Reevaluation," *CVPR 2019*, arXiv:1904.00260. (P-DARTS)  
38. Xu, Y., Xie, L., Zhang, X., Chen, Z., Qi, G.-J., Tian, Q., Wang, H., "PC-DARTS: Partial Channel Connections for Memory-Efficient Differentiable Architecture Search," *ICLR 2020*, arXiv:1907.05737.  
39. Cai, H., Zhu, L., Han, S., "ProxylessNAS: Direct Neural Architecture Search on Target Task and Hardware," *ICLR 2019*, arXiv:1812.00332.  
40. Real, E., Aggarwal, A., Huang, Y., Le, Q.V., "Regularized Evolution for Architectural Design Search: The AmoebaNAS Approach," *AAAI 2019*, arXiv:1802.01548.  
41. Tan, M., Chen, B., Pang, R., Vasudevan, V., Le, Q.V., "MnasNet: Platform-Aware Neural Architecture Search for Mobile," *CVPR 2019*, arXiv:1807.11626.

### Scaling Laws & Compute-Optimal Training

42. Kaplan, J., McCandlish, S., Henighan, T., Brown, T.B., Chess, B., Child, R., Gray, S., et al., "Scaling Laws for Neural Language Models," *arXiv 2020*, arXiv:2001.08361.  
43. Hoffmann, J., Borgeaud, S., Mensch, A., Buchatskaya, E., Cai, T., Rutherford, E., Casas, D., et al., "Training Compute-Optimal Large Language Models," *arXiv 2022*, arXiv:2203.15556. (Chinchilla)  
44. Brown, T.B., Mann, B., Ryder, N., Subbiah, M., Kaplan, J., Dhariwal, P., Neelakantan, A., et al., "Language Models are Few-Shot Learners," *NeurIPS 2020*, arXiv:2005.14165. (GPT-3)  
45. Touvron, H., Lavril, T., Izacard, G., Martinet, X., Lachaux, M.-A., Lacroix, T., Rozière, B., et al., "LLaMA: Open and Efficient Foundation Language Models," *arXiv 2023*, arXiv:2302.13971.  
46. Dubey, A., Jauhri, A., Pandey, A., Kadian, A., Al-Dahle, A., Letman, A., Mathur, A., et al., "The Llama 3 Herd of Models," *arXiv 2024*, arXiv:2407.21783.  
47. Muennighoff, N., Rush, A., Barak, B., Scao, L.L., Tazi, N., Piktus, A., et al., "Scaling Data-Constrained Language Models," *NeurIPS 2023*, arXiv:2305.16264.

### Mixed Precision & Memory Optimization

48. Micikevicius, P., Narang, S., Alben, J., Garcia, G., Ginsburg, B., Houston, T., Kuchaiev, O., et al., "Mixed Precision Training," *ICLR 2018*, arXiv:1710.03712.  
49. Chen, T., Xu, B., Zhang, C., Guestrin, C., "Training Deep Nets with Sublinear Memory Cost," *arXiv 2016*, arXiv:1604.06174. (Gradient checkpointing)  
50. Rajbhandari, S., Ruwase, O., Rasley, J., Smith, S., He, Y., "ZeRO: Memory Optimizations Toward Training Trillion Parameter Models," *SC 2020*, arXiv:1910.02054.  
51. Shoeybi, M., Patwary, M., Puri, R., LeGresley, P., Casper, J., Catanzaro, B., "Megatron-LM: Training Multi-Billion Parameter Language Models Using Model Parallelism," *arXiv 2019*, arXiv:1909.08053.

### Sequence Modeling & State-Space Models

52. Bahdanau, D., Cho, K., Bengio, Y., "Neural Machine Translation by Jointly Learning to Align and Translate," *ICLR 2015*, arXiv:1409.0473.  
53. Hochreiter, S., Schmidhuber, J., "Long Short-Term Memory," *Neural Computation 1997*, DOI:10.1162/neco.1997.9.8.1735.  
54. Gu, A., Goel, K., Ré, C., "Efficiently Modeling Long Sequences with Structured State Spaces," *ICLR 2022*, arXiv:2111.00396. (S4)  
55. Gu, A., Dao, T., "Mamba: Linear-Time Sequence Modeling with Selective State Spaces," *arXiv 2023*, arXiv:2312.00752.

### Initialization & Training Stability

56. Glorot, X., Bengio, Y., "Understanding the Difficulty of Training Deep Feedforward Neural Networks," *AISTATS 2010*. (Xavier initialization)  
57. He, K., Zhang, X., Ren, S., Sun, J., "Delving Deep into Rectifiers: Surpassing Human-Level Performance on ImageNet Classification," *ICCV 2015*, arXiv:1502.01852. (He/Kaiming initialization)  
58. Loshchilov, I., Hutter, F., "Decoupled Weight Decay Regularization," *ICLR 2019*, arXiv:1711.05101. (AdamW)  
59. Smith, L.N., "Cyclical Learning Rates for Training Neural Networks," *WACV 2017*, arXiv:1506.01186.  
60. Loshchilov, I., Hutter, F., "SGDR: Stochastic Gradient Descent with Warm Restarts," *ICLR 2017*, arXiv:1608.03983.

### Squeeze-and-Excitation & Attention Mechanisms

61. Hu, J., Shen, L., Sun, G., "Squeeze-and-Excitation Networks," *CVPR 2018*, arXiv:1709.01507.  
62. Woo, S., Park, J., Lee, J.-Y., Kweon, I.S., "CBAM: Convolutional Block Attention Module," *ECCV 2018*, arXiv:1807.06521.
## References

- He, K. et al., "Deep Residual Learning for Recognizing Image Sequences," CVPR 2016. https://arxiv.org/abs/1512.03385
- Vaswani, A. et al., "Attention Is All You Need," NeurIPS 2017. https://arxiv.org/abs/1706.03762
- Huang, Y. et al., "Swin Transformer: Hierarchical Vision Transformer using Shifted Windows," ICCV 2021. https://arxiv.org/abs/2103.14030
- Dosovitskiy, A. et al., "An Image is Worth 16x16 Words: Transformers for Image Recognition at Scale," ICLR 2021. https://arxiv.org/abs/2010.11929
- Radosavovic, I. et al., "Designing Network Design Spaces," CVPR 2020. https://arxiv.org/abs/2004.05462
- Tan, M. & Le, Q., "EfficientNet: Rethinking Model Scaling for Convolutional Neural Networks," ICML 2019. https://arxiv.org/abs/1905.11946
- Brown, T. et al., "Language Models are Few-Shot Learners," NeurIPS 2020. https://arxiv.org/abs/2005.14165
- Goodfellow, I. et al., "Deep Learning," MIT Press, 2016. https://www.deeplearningbook.org/
- Li, M. et al., "Scaling Laws for Neural Language Models," 2020. https://arxiv.org/abs/2001.08361
- Kaplan, J. et al., "Scaling Laws for Neural Language Models," 2020. https://arxiv.org/abs/2001.08361
