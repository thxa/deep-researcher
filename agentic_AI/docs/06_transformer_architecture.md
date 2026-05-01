# 6. Transformer Architecture: The Backbone of Agentic AI

> "Attention is all you need." — Vaswani et al., 2017

The Transformer is the single most important architectural innovation underpinning modern agentic AI systems. Every large language model—GPT-4, Claude, Llama, Gemini—is a Transformer derivative. Understanding every nut and bolt of this architecture is non-negotiable for anyone building or researching agentic systems.

---

## 6.1 Self-Attention: Mathematical Derivation

### 6.1.1 From Intuition to Equations

Self-attention computes a weighted sum of all positions in a sequence, where the weights are determined dynamically by the relevance of each position to the current position.

Given an input sequence of vectors **X** ∈ ℝ^{n × d} (n tokens, d model dimension):

**Step 1 — Linear Projections.** Three learned weight matrices project the input into queries, keys, and values:

```
Q = X · W_Q     where W_Q ∈ ℝ^{d × d_k}
K = X · W_K     where W_K ∈ ℝ^{d × d_k}
V = X · W_V     where W_V ∈ ℝ^{d × d_v}
```

**Step 2 — Compatibility Scores.** Compute pairwise similarity between every query and every key:

```
S = Q · K^T     S ∈ ℝ^{n × n}
```

Each entry S_{ij} measures how much token i should attend to token j.

**Step 3 — Scaling.** Divide by √d_k to prevent the softmax from saturating in large dimensions (the dot products grow with dimension, pushing softmax into regions with tiny gradients):

```
S_scaled = S / √d_k
```

**Why √d_k?** If q and k are drawn from zero-mean independent distributions with variance d_k, their dot product has variance d_k. Scaling by √d_k restores unit variance, keeping gradients healthy.

**Step 4 — Softmax Normalization.** Row-wise softmax converts scores to attention weights:

```
α_{ij} = exp(S_{ij}^{scaled}) / Σ_k exp(S_{ik}^{scaled})
```

**Step 5 — Weighted Aggregation.** Multiply weights by values:

```
Attention(Q, K, V) = softmax(Q · K^T / √d_k) · V
```

### Full Derivation of Gradients

For the attention output **O = softmax(QK^T / √d_k) · V**, the gradient with respect to Q:

```
∂L/∂Q = (1/√d_k) · W_Q^T · [(∂L/∂O · V^T) ⊙ (α - α·α^T)] · K
```

where ⊙ denotes element-wise multiplication and α is the attention weight matrix. The term (α - α·α^T) is the Jacobian of softmax, which ensures that gradient flow is modulated by the attention distribution itself.

### Scaled Dot-Product Attention — ASCII Diagram

```
                    ┌─────────────── Scaled Dot-Product Attention ───────────────┐
                    │                                                            │
    Q ──┐           │     ┌─────┐      ┌──────────┐      ┌──────────┐           │
       └──┐         │     │     │      │          │      │          │           │
          ├──┬─────► │  ──►│MatMul│──► │ Scale    │──► │ Softmax  │──┐        │
       ┌──┘  │      │     │     │  d_k │ (÷ √d_k) │     │ (row-wise)│  │        │
    K ──┘    │      │     └─────┘      └──────────┘      └──────────┘  │        │
             │      │                                                │        │
             │      │                                                ▼        │
             │      │                                          ┌──────────┐  │
             │      │                                          │  Mask    │  │   (optional)
             │      │                                          │ (causal/ │  │
             │      │                                          │  padding)│  │
             │      │                                          └────┬─────┘  │
             │      │                                               │        │
             │      │                                               ▼        │
             │      │                                         ┌──────────┐   │
             ├──────┼────────────────────────────────────────►│  MatMul  │   │
             │      │                                         └────┬─────┘   │
          V ─┘      │                                              │         │
                    │                                              ▼         │
                    │                                         Output O      │
                    │                                       (n × d_v matrix) │
                    └────────────────────────────────────────────────────────────┘
```

---

## 6.2 Multi-Head Attention

### 6.2.1 Why Multiple Heads?

A single attention head learns one pattern of relating positions. Multiple heads allow the model to attend to information from different representation subspaces simultaneously—one head might focus on syntactic relationships, another on coreference, another on positional proximity.

### 6.2.2 Architecture

Split the model dimension d into h heads, each of dimension d_k = d / h:

```
MultiHead(Q, K, V) = Concat(head_1, ..., head_h) · W_O

where  head_i = Attention(Q·W_Q^i, K·W_K^i, V·W_V^i)
```

Each head operates on a d_k-dimensional subspace. The output projection W_O ∈ ℝ^{h·d_v × d} merges all heads back to model dimension.

### 6.2.3 Implementation

```python
import torch
import torch.nn as nn
import torch.nn.functional as F
import math

class MultiHeadAttention(nn.Module):
    def __init__(self, d_model: int, n_heads: int, dropout: float = 0.1):
        super().__init__()
        assert d_model % n_heads == 0, "d_model must be divisible by n_heads"
        self.d_model = d_model
        self.n_heads = n_heads
        self.d_k = d_model // n_heads

        self.W_Q = nn.Linear(d_model, d_model, bias=False)
        self.W_K = nn.Linear(d_model, d_model, bias=False)
        self.W_V = nn.Linear(d_model, d_model, bias=False)
        self.W_O = nn.Linear(d_model, d_model, bias=False)

        self.dropout = nn.Dropout(dropout)

    def forward(self, query, key, value, mask=None):
        B, S, _ = query.shape

        Q = self.W_Q(query)
        K = self.W_K(key)
        V = self.W_V(value)

        # Reshape: (B, S, d_model) -> (B, n_heads, S, d_k)
        Q = Q.view(B, S, self.n_heads, self.d_k).transpose(1, 2)
        K = K.view(B, S, self.n_heads, self.d_k).transpose(1, 2)
        V = V.view(B, S, self.n_heads, self.d_k).transpose(1, 2)

        # Scaled dot-product attention
        scores = torch.matmul(Q, K.transpose(-2, -1)) / math.sqrt(self.d_k)
        if mask is not None:
            scores = scores.masked_fill(mask == 0, float('-inf'))
        attn_weights = F.softmax(scores, dim=-1)
        attn_weights = self.dropout(attn_weights)

        attn_output = torch.matmul(attn_weights, V)

        # Reshape back: (B, n_heads, S, d_k) -> (B, S, d_model)
        attn_output = attn_output.transpose(1, 2).contiguous().view(B, S, self.d_model)

        return self.W_O(attn_output)
```

### Multi-Head Attention — ASCII Diagram

```
       Input X (B, S, d_model)
               │
    ┌──────────┴──────────┐──────────┐──────────┐
    │                       │          │          │
    ▼                       ▼          ▼          │
  W_Q·X                  W_K·X     W_W_V·X      │
  (B,S,d)                (B,S,d)   (B,S,d)       │
    │                       │          │          │
    ▼                       ▼          ▼          │
  Split into h heads:                          │
  ┌─────────────────────────────────────────┐   │
  │                                         │   │
  │  Head 1: Q₁ K₁ V₁ ──► Attention ──► h₁ │   │
  │  Head 2: Q₂ K₂ V₂ ──► Attention ──► h₂ │   │
  │  Head 3: Q₃ K₃ V₃ ──► Attention ──► h₃ │   │
  │   ...         ...          ...      ...  │   │
  │  Head h: Qₕ Kₕ Vₕ ──► Attention ──► hₕ │   │
  │                                         │   │
  └─────────────────────────────────────────┘   │
    │                                            │
    ▼                                            │
  Concat(h₁,...,hₕ)                             │
  (B, S, h·d_k) = (B, S, d_model)               │
    │                                            │
    ▼                                            │
  ┌─────────┐                                    │
  │  W_O    │◄───────────────────────────────────┘
  │(d, d)   │
  └────┬────┘
       │
       ▼
  Output (B, S, d_model)
```

---

## 6.3 Positional Encoding

Transformers have no inherent notion of order—attention is permutation equivariant. Positional encoding injects sequence position information.

### 6.3.1 Sinusoidal Positional Encoding (Original Transformer)

```
PE(pos, 2i)   = sin(pos / 10000^{2i/d_model})
PE(pos, 2i+1) = cos(pos / 10000^{2i/d_model})
```

Properties:
- Fixed, not learned—zero parameters
- Allows model to learn relative positions via linear transformations: PE(pos+k) is a linear function of PE(pos)
- Generalizes to unseen sequence lengths

### 6.3.2 Learned Positional Embeddings

Simply an embedding table `nn.Embedding(max_seq_len, d_model)`. Used in BERT, GPT-2, GPT-3.

- Pros: More flexible, can learn task-specific positional patterns
- Cons: Cannot extrapolate beyond training max length; adds parameters

### 6.3.3 Rotary Positional Embedding (RoPE)

RoPE (Su et al., 2021) encodes position by rotating query and key vectors, making the dot product between Q and K depend only on relative position:

```
q_m = q · R(Θ, m)
k_n = k · R(Θ, n)

⟨q_m, k_n⟩ depends only on (m - n)
```

Where R is a block-diagonal rotation matrix:

```
R(Θ, m) = diag(R(θ₁,m), R(θ₂,m), ..., R(θ_{d/2},m))

R(θ_i, m) = | cos(m·θ_i)  -sin(m·θ_i) |
             | sin(m·θ_i)   cos(m·θ_i) |

θ_i = 10000^{-2i/d}
```

Used in: Llama, PaLM, Falcon, Qwen, Mistral, and nearly all modern LLMs.

### 6.3.4 ALiBi (Attention with Linear Biases)

ALiBi (Press et al., 2022) injects position by adding a static bias to attention scores:

```
softmax(q_i · k_j + m · (i - j))
```

Where m is a head-specific negative slope (e.g., 2^{-8}, 2^{-4}, ...). No positional embeddings needed. Enables length extrapolation.

### Positional Encoding — Comparison Diagram

```
  Sinusoidal                              Learned
  ──────────                              ───────

  Dim 0 (sin) ─╮                          ┌── Embedding Table ──┐
  Dim 1 (cos) ─┤                          │ pos 0 → [0.1, ...] │
  Dim 2 (sin) ─┤ zigzag                   │ pos 1 → [0.3, ...] │
  Dim 3 (cos) ─┤ pattern                 │ pos 2 → [0.8, ...] │
  ...          ─┤                         │        ...          │
  Dim d (cos) ──╯                          │ pos N → [0.2, ...] │
                                           └─────────────────────┘
  *fixed* *deterministic*                  *learned* *trainable*
  *extrapolates*                            *bounded by max_len*


  RoPE                                     ALiBi
  ────                                     ─────

  Rotates Q and K vectors:                 Adds bias to attention:
                                           ┌───────────────────────────────┐
  ┌──────────────────┐                     │  Q·K^T + m · [ 0  -1  -2  -3] │
  │  Q ──► rotate    │                     │              [ 0   0  -1  -2] │
  │  K ──► rotate    │                     │              [ 0   0   0  -1] │
  │  by pos angle    │                     │              [ 0   0   0   0] │
  └──────────────────┘                     └───────────────────────────────┘
  *relative position only*                 *linear bias per head*
  *used in Llama, PaLM*                   *no embeddings needed*
```

---

## 6.4 Layer Normalization: LayerNorm, RMSNorm, and Placement

### 6.4.1 Layer Normalization

```
LayerNorm(x) = γ ⊙ (x - μ) / σ + β

where  μ  = (1/d) Σᵢ xᵢ
       σ² = (1/d) Σᵢ (xᵢ - μ)²
       σ  = √(σ² + ε)
```

γ and β are learnable parameters of dimension d. Normalizes across the feature dimension for each token independently.

### 6.4.2 RMSNorm (Root Mean Square Normalization)

RMSNorm (Zhang & Sennrich, 2019) simplifies LayerNorm by removing the mean-centering:

```
RMSNorm(x) = γ ⊙ x / RMS(x)

where  RMS(x) = √((1/d) Σᵢ xᵢ² + ε)
```

No β parameter needed. Computationally cheaper (~7-10% faster), empirically equivalent quality. Used in Llama, Mistral, and most modern LLMs.

### 6.4.3 Placement: Pre-Norm vs Post-Norm

```
  Pre-Norm (modern standard)              Post-Norm (original Transformer)
  ────────────────────────                ──────────────────────────────────

    x ──► LayerNorm ──► Attn ──► + ──►     x ──► Attn ──► + ──► LayerNorm ──►
    │                      ▲                │         ▲           │
    └──────────────────────┘                └─────────┘           ▼
         residual connection               residual        next sublayer

    More stable gradients                   Risk of gradient
    No need for warmup                       explosion/vanishing
    Used in GPT-2+, Llama, ...              Used in original Transformer, BERT
```

**Why pre-norm won:** In post-norm, the residual path passes through LayerNorm, which rescales gradients and can destabilize early training. Pre-norm preserves the residual highway intact, making the gradient path from output to input essentially identity—a critical insight for training deep transformers (100+ layers).

---

## 6.5 Feed-Forward Networks in Transformers

### 6.5.1 Standard FFN

```
FFN(x) = W₂ · σ(W₁ · x + b₁) + b₂

W₁ ∈ ℝ^{d × d_ff},  W₂ ∈ ℝ^{d_ff × d}
d_ff = 4 × d_model  (standard expansion factor)
σ = ReLU (original) or GELU (modern)
```

The FFN is where the model stores knowledge and performs computation. The expansion to 4× provides representational capacity—the network can memorize and recall facts.

### 6.5.2 Activation Functions

```
ReLU(x)     = max(0, x)                         # Simplest, original
GELU(x)     = x · Φ(x)  ≈ x · σ(1.702x)       # Smooth ReLU; GPT-2/3
Swish(x)    = x · σ(βx)                         # Generalization of GELU
SiLU(x)     = x · σ(x)   (= Swish with β=1)     # Llama, Mistral
GLU variants:                                    # Modern standard
  SwiGLU(x) = (x · σ(x)) ⊙ (W_gate · x)        # Llama 2/3, PaLM
  GeGLU(x)  = GELU(x) ⊙ (W_gate · x)            # PaLM
```

### 6.5.3 SwiGLU (the modern default)

Shazeer (2020) showed that gating mechanisms improve over plain FFNs:

```
FFN_SwiGLU(x) = (Swish(W_gate · x) ⊙ W_up · x) · W_down

where W_gate, W_up ∈ ℝ^{d × d_ff}, W_down ∈ ℝ^{d_ff × d}
```

Note: with SwiGLU, the expansion factor is typically 8/3 × d rather than 4d to keep parameter count comparable.

---

## 6.6 Architecture Variants

### 6.6.1 Encoder-Only: BERT

BERT uses bidirectional attention—every token attends to every other token. Trained with masked language modeling (MLM).

```
            ┌──────────────── BERT (Encoder-Only) ────────────────┐
            │                                                      │
  Input:    │  [CLS] The cat sat on the [MASK]                      │
            │     │   │   │   │   │    │                            │
            │     ▼   ▼   ▼   ▼   ▼    ▼                            │
            │  ┌──────────────────────────────┐                     │
            │  │ Token Emb + Seg Emb + Pos Emb │                     │
            │  └──────────────┬───────────────┘                     │
            │                 ▼                                     │
            │  ┌──────────────────────────────┐                     │
            │  │     Multi-Head Attention      │◄── FULL (bidir)    │
            │  │     + Add & Norm             │                     │
            │  ├──────────────────────────────┤                     │
            │  │     Feed-Forward             │                     │
            │  │     + Add & Norm             │                     │
            │  └──────────────┬───────────────┘                     │
            │                 ▼ (×N layers)                         │
            │  ┌──────────────────────────────┐                     │
            │  │ [CLS] → Classification Head  │                     │
            │  │ Other → Masked Token Preds    │                     │
            │  └──────────────────────────────┘                     │
            └──────────────────────────────────────────────────────┘

  Use cases: Classification, NER, QA (extractive), semantic similarity
```

### 6.6.2 Decoder-Only: GPT

GPT uses causal (autoregressive) attention—each token can only attend to preceding tokens. Trained with next-token prediction.

```
               ┌─────────────── GPT (Decoder-Only) ───────────────┐
               │                                                   │
  Input:       │  The cat sat on the                               │
               │    │   │   │   │   │                              │
               │    ▼   ▼   ▼   ▼   ▼                              │
               │ ┌────────────────────────────────────┐             │
               │ │ Token Embedding + Positional Embed  │             │
               │ └──────────────┬─────────────────────┘             │
               │                ▼                                   │
               │ ┌────────────────────────────────────┐             │
               │ │ Masked Multi-Head Attention         │◄── CAUSAL │
               │ │ + Add & Norm                        │    mask   │
               │ ├────────────────────────────────────┤             │
               │ │ Feed-Forward (SwiGLU)               │             │
               │ │ + Add & Norm                        │             │
               │ └──────────────┬─────────────────────┘             │
               │                ▼ (×N layers)                       │
               │ ┌────────────────────────────────────┐             │
               │ │ LayerNorm → Linear → Softmax      │             │
               │ │ (vocab projection, no weight tied) │             │
               │ └──────────────┬─────────────────────┘             │
               │                ▼                                   │
               │         next token prediction                      │
               └───────────────────────────────────────────────────┘

  Use cases: Text generation, chat, code, agentic reasoning
```

### 6.6.3 Encoder-Decoder: T5

T5 uses an encoder for bidirectional processing and a decoder for autoregressive generation, connected by cross-attention.

```
  ┌─────────────────── T5 (Encoder-Decoder) ───────────────────┐
  │                                                             │
  │  ENCODER (bidirectional)        DECODER (autoregressive)   │
  │                                                             │
  │  "Translate this       ──►   ┌─────────────────────┐       │
  │   text to French:"           │ Cross-Attention      │       │
  │         │                    │ Q from decoder       │       │
  │         ▼                    │ K,V from encoder    │       │
  │  ┌────────────────┐   ┌─────┴─────────────────────┘       │
  │  │ Self-Attention  │   │                                   │
  │  │ (FULL mask)     │   │  ┌─────────────────────┐         │
  │  │ + Add & Norm    │   │  │ Masked Self-Attention│         │
  │  ├────────────────┤   │  │ (CAUSAL mask)        │         │
  │  │ Feed-Forward    │   │  │ + Add & Norm          │         │
  │  │ + Add & Norm    │   │  ├─────────────────────┤         │
  │  └───────┬────────┘   │  │ Cross-Attention       │◄─────── │
  │          │(×N)         │  │ + Add & Norm          │         │
  │          │             │  ├─────────────────────┤         │
  │          └─────────────┤  │ Feed-Forward          │         │
  │                        │  │ + Add & Norm          │         │
  │                        │  └──────────┬──────────┘         │
  │                        │             ▼ (×N)                 │
  │                        │      Linear → Softmax             │
  │                        │      "Bonjour le monde"            │
  └─────────────────────────────────────────────────────────────┘

  Use cases: Translation, summarization, structured generation
```

### Encoder vs Decoder Block — Side-by-Side

```
   ENCODER BLOCK                            DECODER BLOCK
   ═════════════                            ═════════════

   Input                                     Input (shifted right)
     │                                          │
     ▼                                          ▼
   ┌────────────────┐                       ┌────────────────┐
   │  LayerNorm     │                       │  LayerNorm     │
   └───────┬────────┘                       └───────┬────────┘
           ▼                                        ▼
   ┌────────────────┐                       ┌────────────────┐
   │ Multi-Head     │◄── No mask           │ Masked Multi-   │◄── Causal mask
   │ Self-Attention │    (bidirectional)    │ Head Attention  │    (autoregressive)
   └───────┬────────┘                       └───────┬────────┘
           │                                        │
     ┌─────┘                                        │
     │    ┌─────────┐                        ┌─────┘
     │   │  + Add  │◄── residual             │    ┌─────────┐
     │    └────┬────┘                        │   │  + Add  │◄── residual
     │         ▼                             │    └────┬────┘
     │  ┌────────────────┐                  │         ▼
     │  │  LayerNorm     │                  │  ┌────────────────┐
     │  └───────┬────────┘                  │  │  LayerNorm     │
     │          ▼                            │  └───────┬────────┘
     │  ┌────────────────┐                  │          ▼
     │  │ Feed-Forward  │                  │  ┌────────────────┐
     │  │ (SwiGLU)      │                  │  │ Cross-Attention │◄── K,V from
     │  └───────┬────────┘                  │  │ + Add           │    encoder
     │          │                            │  └───────┬────────┘
     │    ┌─────┘                            │          │
     │    │  ┌─────────┐                     │    ┌─────┤
     │    └─►│  + Add  │◄── residual        │    │  ┌─────────┐
     │       └────┬────┘                     │    └─►│  + Add  │◄── residual
     │            ▼                           │       └────┬────┘
     │    ┌────────────────┐                  │            ▼
     │    │  Output        │                  │    ┌────────────────┐
     │    └────────────────┘                  │    │  LayerNorm     │
     │                                         │    └───────┬────────┘
     │                                         │            ▼
     │                                         │    ┌────────────────┐
     │                                         │    │ Feed-Forward  │
     │                                         │    │ (SwiGLU)      │
     │                                         │    └───────┬────────┘
     │                                         │    ┌──────┘
     │                                         │    │  ┌─────────┐
     │                                         │    └─►│  + Add  │◄── residual
     │                                         │       └────┬────┘
     │                                         │            ▼
     │                                         │    ┌────────────────┐
     │                                         │    │  Output        │
     │                                         │    └────────────────┘
```

---

## 6.7 Efficient Attention Variants

### 6.7.1 Flash Attention

Flash Attention (Dao et al., 2022) is an exact attention algorithm (not an approximation) that minimizes HBM (high-bandwidth memory) reads/writes by tiling the computation through SRAM.

**Key insight:** Standard materializes the full n×n attention matrix in HBM. Flash Attention computes attention in blocks, keeping intermediate results in fast SRAM, and only writes the final output to HBM.

```
  Standard Attention                      Flash Attention
  ═══════════════════                      ════════════════

  HBM                                     HBM
  ┌──────────────────┐                    ┌──────────────────┐
  │ Q, K, V           │                    │ Q, K, V           │
  │   │               │                    │   │               │
  │   ▼               │                    │   ▼               │
  │ S = QK^T (n×n)    │ ◄── O(n²) HBM     │   │ Load blocks   │
  │   │               │     write          │   ▼ into SRAM    │
  │   ▼               │                    │ ┌────────────────┐│
  │ P = softmax(S)    │ ◄── O(n²) HBM     │ │ SRAM (fast)     ││
  │   │               │     write          │ │ ┌────────────┐ ││
  │   ▼               │                    │ │ │ Compute    │ ││
  │ O = P·V           │ ◄── O(n²) HBM     │ │ │ block of   │ ││
  │                   │     read           │ │ │ attention  │ ││
  │ Memory: O(n²)     │                    │ │ │ in SRAM    │ ││
  │ Wall time: slow   │                    │ │ └────────────┘ ││
  └──────────────────┘                    │ │ Online softmax ││
                                          │ │ (cumulative)   ││
                                          │ └──────┬─────────┘│
                                          │        ▼           │
                                          │ Write O to HBM    │
                                          │                   │
                                          │ Memory: O(n)      │
                                          │ Wall time: ~2-4×  │
                                          └──────────────────┘

  Flash Attention Memory Layout (block tiling):
  ┌────────────────────────────────────────────────────────────┐
  │  Q is split into blocks of B_r rows                        │
  │  K, V are split into blocks of B_c rows                    │
  │                                                            │
  │         K₁      K₂      K₃      K₄                        │
  │      ┌──────┬──────┬──────┬──────┐                          │
  │  Q₁  │  ●   │  ●   │  ●   │  ●   │  ○ = partial           │
  │      ├──────┼──────┼──────┼──────┤    softmax result        │
  │  Q₂  │  ●   │  ●   │  ●   │  ●   │    computed in SRAM    │
  │      ├──────┼──────┼──────┼──────┤                         │
  │  Q₃  │  ●   │  ●   │  ●   │  ●   │                         │
  │      └──────┴──────┴──────┴──────┘                          │
  │                                                            │
  │  Each ●: load Q_block, K_block to SRAM                    │
  │          compute partial softmax (with online correction)    │
  │          accumulate O_block in SRAM                         │
  │          write O_block to HBM only when complete            │
  └────────────────────────────────────────────────────────────┘
```

**Online Softmax Correction:** Since softmax requires global normalization, Flash Attention uses the log-sum-exp trick across blocks:

```
m^(j) = max(m^(j-1), rowmax(Q_i · K_j^T / √d_k))    # running max
ℓ^(j) = e^{m^(j-1) - m^(j)} · ℓ^(j-1) + rowsum(exp(Q_i · K_j^T / √d_k - m^(j)))
O^(j) = e^{m^(j-1) - m^(j)} · O^(j-1) + V_j · softmax(...)
```

Flash Attention 2 further reduces non-matmul FLOPs and improves parallelism.

### 6.7.2 Linear Attention

Approximate softmax attention with a kernel feature map φ:

```
Attention(Q, K, V) = softmax(QK^T)V
                    ≈ (φ(Q) · (φ(K)^T · V)) / (φ(Q) · (φ(K)^T · 1))
```

By computing φ(K)^T · V first (d×d instead of n×n), complexity drops from O(n²d) to O(nd²).

Variants: Performer (random Fourier features), Linear Transformer (ELU+1 feature map), RWKV (weighted linear attention).

### 6.7.3 Sparse Attention

Only attend to a subset of positions rather than all n:

```
  ┌─────────────────── Sparse Attention Patterns ───────────────────┐
  │                                                                 │
  │  Local (sliding window):        Strided (dilated):              │
  │  ┌───────────────────┐          ┌───────────────────┐           │
  │  │ ██ ░░ ░░ ░░ ░░ ░░ │          │ ██ ░░ ░░ ██ ░░ ░░ │           │
  │  │ ██ ██ ░░ ░░ ░░ ░░ │          │ ██ ░░ ░░ ██ ░░ ░░ │           │
  │  │ ░░ ██ ██ ░░ ░░ ░░ │          │ ░░ ██ ░░ ░░ ██ ░░ │           │
  │  │ ░░ ░░ ██ ██ ░░ ░░ │          │ ░░ ██ ░░ ░░ ██ ░░ │           │
  │  │ ░░ ░░ ░░ ██ ██ ░░ │          │ ░░ ░░ ██ ░░ ░░ ██ │           │
  │  │ ░░ ░░ ░░ ░░ ██ ██ │          │ ░░ ░░ ██ ░░ ░░ ██ │           │
  │  └───────────────────┘          └───────────────────┘           │
  │                                                                 │
  │  Global + Local:                Longformer-style:               │
  │  ┌───────────────────┐          ┌───────────────────┐           │
  │  │ ██ ██ ██ ██ ██ ██ │          │ ██ ░░ ░░ ██ ░░ ░░ │           │
  │  │ ██ ██ ░░ ░░ ░░ ░░ │          │ ██ ██ ░░ ░░ ░░ ░░ │           │
  │  │ ██ ░░ ██ ░░ ░░ ░░ │          │ ░░ ██ ██ ░░ ░░ ░░ │           │
  │  │ ██ ░░ ░░ ██ ░░ ░░ │          │ ░░ ░░ ██ ██ ░░ ░░ │           │
  │  │ ██ ░░ ░░ ░░ ██ ░░ │          │ ░░ ░░ ░░ ██ ██ ░░ │           │
  │  │ ██ ░░ ░░ ░░ ░░ ██ │          │ ██ ░░ ░░ ░░ ██ ██ │           │
  │  └───────────────────┘          └───────────────────┘           │
  │  (first token sees all)          (local window + select         │
  │                                   global tokens)                 │
  └─────────────────────────────────────────────────────────────────┘
```

### 6.7.4 Multi-Query Attention (MQA) & Grouped-Query Attention (GQA)

```
  Standard MHA                          MQA
  ════════════                          ═══

  Q: h heads                            Q: h heads
  K: h heads                            K: 1 head ← shared!
  V: h heads                            V: 1 head ← shared!

  ┌─Head1── Q₁ K₁ V₁ ─┐               ┌─Head1── Q₁ K V ─┐
  │  Head2── Q₂ K₂ V₂  │               │  Head2── Q₂ K V  │
  │  Head3── Q₃ K₃ V₃  │               │  Head3── Q₃ K V  │
  │  Head4── Q₄ K₄ V₄  │               │  Head4── Q₄ K V  │
  └─────────────────────┘               └──────────────────┘
  KV cache: O(n · h · d)                KV cache: O(n · d)
                                            ↓
                                       97% KV cache reduction
                                       (used in PaLM, Falcon)

  GQA (Grouped-Query Attention)
  ═══════════════════════════════

  Q: h heads, K/V: g groups (g < h)
  Each group of (h/g) query heads shares one K/V head

  ┌─Group1── Q₁ Q₂ ── K₁ V₁ ─┐
  │  Group2── Q₃ Q₄ ── K₂ V₂  │
  │  Group3── Q₅ Q₆ ── K₃ V₃  │
  │  Group4── Q₇ Q₈ ── K₄ V₄  │
  └──────────────────────────────┘
  h=8 heads, g=4 groups
  KV cache: O(n · g · d) — middle ground
  Used in: Llama 2 (g=8→1), Llama 3 (g=8)
```

**Comparison table:**

| Method | KV Heads | KV Cache | Quality | Speed |
|--------|----------|----------|---------|-------|
| MHA | h | O(nhd) | Best | Slowest |
| GQA | g (1<g<h) | O(ngd) | Near MHA | Fast |
| MQA | 1 | O(nd) | Slight drop | Fastest |

---

## 6.8 Mixture of Experts (MoE)

### 6.8.1 Architecture

MoE replaces the dense FFN with multiple expert FFNs and a gating/router network that selects a sparse subset per token:

```
FFN_MoE(x) = Σᵢ g_i(x) · E_i(x)

where g_i(x) = TopK(Softmax(W_gate · x))   # router selects k experts
      E_i(x) = standard SwiGLU FFN          # expert i
```

Typically k=1 or k=2 out of 8-256 experts. Only 1-2 experts are activated per token → compute-efficient.

### 6.8.2 MoE Routing Diagram

```
  ┌───────────────────── Mixture of Experts ──────────────────────┐
  │                                                                │
  │  Input token x                                                 │
  │       │                                                        │
  │       ▼                                                        │
  │  ┌────────────────┐                                            │
  │  │ Router / Gate  │                                             │
  │  │ W_gate ∈ ℝ^{d×E}│                                            │
  │  └──────┬─────────┘                                            │
  │         │                                                      │
  │    softmax logits                                              │
  │         │                                                      │
  │    ┌────┴────┐                                                 │
  │    │  Top-K  │  (k=2)                                          │
  │    └────┬────┘                                                 │
  │         │                                                      │
  │    ┌────┴──────────────────────────────────────┐               │
  │    │                                             │               │
  │    ▼                                             ▼               │
  │  Expert 3: g₃=0.6                          Expert 7: g₇=0.4    │
  │  ┌─────────────────┐                        ┌─────────────────┐ │
  │  │ W_down(SwiGLU(  │                        │ W_down(SwiGLU(  │ │
  │  │  W_up(x)))      │                        │  W_up(x)))      │ │
  │  └────────┬────────┘                        └────────┬────────┘ │
  │           │                                          │          │
  │           ▼                                          ▼          │
  │      0.6 · E₃(x)                             0.4 · E₇(x)       │
  │           │                                          │          │
  │           └──────────────┬───────────────────────────┘          │
  │                          ▼                                      │
  │                    Σ gᵢ · Eᵢ(x)                                │
  │                    = 0.6·E₃ + 0.4·E₇                           │
  │                          │                                      │
  │                          ▼                                      │
  │                    Output y                                      │
  │                                                                │
  │  ┌──────────────── Full Expert Pool ────────────────────────┐   │
  │  │ E₀ │ E₁ │ E₂ │ E₃●│ E₄ │ E₅ │ E₆ │ E₇●│ E₈ │ ... │   │
  │  └──────────────────────────────────────────────────────────┘   │
  │                           ● = activated expert                 │
  └────────────────────────────────────────────────────────────────┘
```

### 6.8.3 Load Balancing

The router can collapse—sending all tokens to the same experts, starving others. Solutions:

**Auxiliary loss** (Shazeer et al., 2017):
```
L_aux = α · N · Σᵢ fᵢ · Pᵢ

where fᵢ = fraction of tokens routed to expert i
      Pᵢ = fraction of router probability allocated to expert i
      α ≈ 0.01 (scaling factor)
```

This encourages uniform expert utilization. fᵢ is discrete (non-differentiable); Pᵢ is continuous (differentiable).

**Expert Choice routing** (Zhou et al., 2022): Let experts choose tokens instead of tokens choosing experts. Guarantees perfect load balance.

### 6.8.4 Notable MoE Models

| Model | Experts | Active | Params | Active Params |
|-------|---------|--------|--------|---------------|
| Mixtral 8x7B | 8 | 2 | 46.7B | 12.9B |
| Switch Transformer | 128 | 1 | 1.6T | ~1.6B/tok |
| DeepSeek-V3 | 256 | 8 | 671B | 37B |
| GLaM | 64 | 2 | 1.375T | ~39.5B |

---

## 6.9 State Space Models as an Alternative

### 6.9.1 The Core Idea

State Space Models (SSMs) replace attention with a recurrent/convolutional formulation that is linear in sequence length:

```
SSM:  x'(t) = A·x(t) + B·u(t)    (state equation)
      y(t)  = C·x(t) + D·u(t)    (output equation)

Discretized (ZOH):
      x_k = Ā·x_{k-1} + B̄·u_k
      y_k = C̄·x_k + D̄·u_k
```

Where Ā, B̄, C̄ are learned discretized parameters derived from continuous A, B, C.

### 6.9.2 Mamba (Selective State Space Model)

Mamba (Gu & Dao, 2023) makes SSM parameters input-dependent (selective):

```
Standard SSM:  B, C, Δ are FIXED → content-agnostic
Mamba:         B(x), C(x), Δ(x) are FUNCTIONS OF INPUT → selective
```

This enables the model to selectively remember or forget information—bridge the gap between SSMs and attention.

```
  ┌──────────────── Mamba Block ────────────────┐
  │                                              │
  │  x ──► Linear ──► σ ──► Linear ──► has_skip  │
  │  │              (SiLU)                       │
  │  │                  │                        │
  │  │                  ▼                        │
  │  │            ┌───────────────┐              │
  │  │            │  Conv1d       │              │
  │  │            │  (causal)     │              │
  │  │            └───────┬───────┘              │
  │  │                    ▼                      │
  │  │            ┌───────────────┐              │
  │  │            │  SiLU         │              │
  │  │            └───────┬───────┘              │
  │  │                    │                      │
  │  │                    ▼                      │
  │  │            ┌───────────────┐              │
  │  │            │  Selective SSM │              │
  │  │            │  (input-dep    │              │
  │  │            │   B, C, Δ)     │              │
  │  │            └───────┬───────┘              │
  │  │                    │                      │
  │  │                    ▼                      │
  │  │            ┌───────────────┐              │
  │  │            │  × (gate from │              │
  │  │            │  residual)    │              │
  │  │            └───────┬───────┘              │
  │  │                    │                      │
  │  └────────────────────┘                      │
  │       │                                      │
  │       ▼                                      │
  │  x + output                                  │
  └──────────────────────────────────────────────┘

  Selective SSM sweep (parallel scan):
  ┌─────────────────────────────────────────────────────┐
  │  u₁ → ┌─────┐ → y₁    u₂ → ┌─────┐ → y₂    ...   │
  │       │ SSM │               │ SSM │                  │
  │       │ ĀB̄C̄ │               │ ĀB̄C̄ │                  │
  │       └─────┘               └─────┘                  │
  │  (B,C,Δ vary per token → selective)                 │
  │  Training: parallel scan (O(n log n))               │
  │  Inference: recurrence (O(1) per step!)             │
  └─────────────────────────────────────────────────────┘

  Complexity comparison:
  ┌──────────────┬──────────────┬──────────────┬──────────────┐
  │              │  Training    │  Inference   │  Memory      │
  │              │  (per token) │  (per token) │  (per layer) │
  ├──────────────┼──────────────┼──────────────┼──────────────┤
  │  Attention   │  O(n²)       │  O(n) w/KV   │  O(n²)       │
  │  SSM/Mamba   │  O(n log n)  │  O(1)        │  O(n)        │
  │  Linear Attn │  O(n)        │  O(d²)        │  O(n)        │
  └──────────────┴──────────────┴──────────────┴──────────────┘
```

### 6.9.3 Hybrid Architectures

Modern practice often combines SSM layers with attention layers for the best of both worlds:

- **Jamba** (AI21): Mamba layers + attention layers + MoE
- **Mamba-2**: Structured state space duality—connections between SSMs and structured attention
- **Griffin & Hawk** (Google): Recurrent blocks + local attention

---

## 6.10 Building a Transformer From Scratch

### 6.10.1 Complete Transformer Block Anatomy

```
  ┌────────══─── Complete Transformer Block (Pre-Norm) ───────────────┐
  │                                                                     │
  │  x_in ──┬─────────────────────────────────────────────────────┐    │
  │          │                                                     │    │
  │          ▼                                                     │    │
  │     ┌──────────┐                                               │    │
  │     │RMSNorm   │                                               │    │
  │     │(or LN)   │                                               │    │
  │     └────┬─────┘                                               │    │
  │          │                                                     │    │
  │          ▼                                                     │    │
  │     ┌──────────────────────────────────┐                       │    │
  │     │      Multi-Head Attention         │                       │    │
  │     │  ┌────────┐  ┌────────┐  ┌─────┐ │                       │    │
  │     │  │ W_Q    │  │ W_K    │  │W_V  │ │                       │    │
  │     │  │(d,d)   │  │(d,d)   │  │(d,d)│ │                       │    │
  │     │  └───┬────┘  └───┬────┘  └──┬──┘ │                       │    │
  │     │      │            │          │    │                       │    │
  │     │      ▼            ▼          ▼    │                       │    │
  │     │    Q_h          K_h        V_h   │                       │    │
  │     │      │            │          │    │                       │    │
  │     │      ▼            ▼          │    │                       │    │
  │     │    Q·K^T/√d_k    │          │    │                       │    │
  │     │      │            │          │    │                       │    │
  │     │      ▼            │          │    │                       │    │
  │     │    + mask         │          │    │                       │    │
  │     │      │            │          │    │                       │    │
  │     │      ▼            │          │    │                       │    │
  │     │    softmax         │          │    │                       │    │
  │     │      │            │          │    │                       │    │
  │     │      ▼            │          │    │                       │    │
  │     │    dropout         │          │    │                       │    │
  │     │      │            │          │    │                       │    │
  │     │      ▼            │          │    │                       │    │
  │     │    Attn_weights · V_h       │    │                       │    │
  │     │      │                     │    │                       │    │
  │     │      ▼                     │    │                       │    │
  │     │    Concat heads · W_O      │    │                       │    │
  │     │      │                     │    │                       │    │
  │     │      ▼                     │    │                       │    │
  │     │    dropout                 │    │                       │    │
  │     └──────┬─────────────────────┘    │                       │    │
  │            │                          │                       │    │
  │            ▼                          │                       │    │
  │     ┌──────────┐                      │                       │    │
  │     │  + Add   │◄─────────────────────┘  (residual)          │    │
  │     └────┬─────┘                                              │    │
  │          │                                                    │    │
  │          ▼                                                    │    │
  │     ┌──────────┐                                              │    │
  │     │RMSNorm   │                                              │    │
  │     └────┬─────┘                                              │    │
  │          │                                                    │    │
  │          ▼                                                    │    │
  │     ┌──────────────────┐                                      │    │
  │     │  Feed-Forward    │                                      │    │
  │     │  (SwiGLU)        │                                      │    │
  │     │                  │                                      │    │
  │     │  ┌───────────┐  │                                      │    │
  │     │  │  W_up     │  │                                      │    │
  │     │  │  (d→d_ff) │  │                                      │    │
  │     │  └─────┬─────┘  │                                      │    │
  │     │        │        │                                      │    │
  │     │        ▼        │                                      │    │
  │     │  ┌───────────┐  │                                      │    │
  │     │  │  W_gate   │  │                                      │    │
  │     │  │  (d→d_ff) │  │                                      │    │
  │     │  └─────┬─────┘  │                                      │    │
  │     │        │        │                                      │    │
  │     │        ▼        │                                      │    │
  │     │  SiLU(W_gate)   │                                      │    │
  │     │        │        │                                      │    │
  │     │        ▼        │                                      │    │
  │     │  ⊙ (elementwise)│                                      │    │
  │     │        │        │                                      │    │
  │     │        ▼        │                                      │    │
  │     │  ┌───────────┐  │                                      │    │
  │     │  │  W_down   │  │                                      │    │
  │     │  │(d_ff→d)   │  │                                      │    │
  │     │  └─────┬─────┘  │                                      │    │
  │     │        │        │                                      │    │
  │     │        ▼        │                                      │    │
  │     │    dropout      │                                      │    │
  │     └──────┬──────────┘                                      │    │
  │            │                                                 │    │
  │            ▼                                                 │    │
  │     ┌──────────┐                                             │    │
  │     │  + Add   │◄────────────────────────────────────────────┘    │
  │     └────┬─────┘  (residual)                                       │
  │          │                                                         │
  │          ▼                                                         │
  │       x_out                                                        │
  └─────────────────────────────────────────────────────────────────────┘
```

### 6.10.2 Step-by-Step Implementation

Below is a complete, production-quality GPT-style decoder-only transformer built from scratch:

```python
import torch
import torch.nn as nn
import torch.nn.functional as F
import math
from dataclasses import dataclass


@dataclass
class TransformerConfig:
    vocab_size: int = 32000
    max_seq_len: int = 4096
    d_model: int = 4096
    n_layers: int = 32
    n_heads: int = 32
    n_kv_heads: int = 8          # GQA: 8 KV heads for 32 query heads
    ff_dim: int = 11008          # ~2.7x d_model for SwiGLU
    dropout: float = 0.0
    rope_theta: float = 10000.0
    norm_eps: float = 1e-5


class RMSNorm(nn.Module):
    def __init__(self, dim: int, eps: float = 1e-5):
        super().__init__()
        self.eps = eps
        self.weight = nn.Parameter(torch.ones(dim))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        rms = torch.sqrt(torch.mean(x * x, dim=-1, keepdim=True) + self.eps)
        return x / rms * self.weight


class RotaryEmbedding(nn.Module):
    def __init__(self, dim: int, max_seq_len: int = 4096, theta: float = 10000.0):
        super().__init__()
        inv_freq = 1.0 / (theta ** (torch.arange(0, dim, 2).float() / dim))
        self.register_buffer("inv_freq", inv_freq)
        self.max_seq_len = max_seq_len
        self._set_cos_sin_cache(max_seq_len)

    def _set_cos_sin_cache(self, seq_len: int):
        t = torch.arange(seq_len, device=self.inv_freq.device).float()
        freqs = torch.outer(t, self.inv_freq)
        emb = torch.cat((freqs, freqs), dim=-1)
        self.register_buffer("cos_cached", emb.cos().to(torch.float32), persistent=False)
        self.register_buffer("sin_cached", emb.sin().to(torch.float32), persistent=False)

    def forward(self, seq_len: int):
        return (
            self.cos_cached[:seq_len].unsqueeze(0).unsqueeze(0),
            self.sin_cached[:seq_len].unsqueeze(0).unsqueeze(0),
        )


def apply_rotary_emb(x: torch.Tensor, cos: torch.Tensor, sin: torch.Tensor) -> torch.Tensor:
    d = x.shape[-1] // 2
    x1, x2 = x[..., :d], x[..., d:]
    return torch.cat((x1 * cos - x2 * sin, x1 * sin + x2 * cos), dim=-1)


class GroupedQueryAttention(nn.Module):
    def __init__(self, config: TransformerConfig):
        super().__init__()
        self.n_heads = config.n_heads
        self.n_kv_heads = config.n_kv_heads
        self.n_groups = config.n_heads // config.n_kv_heads
        self.d_model = config.d_model
        self.d_k = config.d_model // config.n_heads

        self.W_Q = nn.Linear(config.d_model, config.n_heads * self.d_k, bias=False)
        self.W_K = nn.Linear(config.d_model, config.n_kv_heads * self.d_k, bias=False)
        self.W_V = nn.Linear(config.d_model, config.n_kv_heads * self.d_k, bias=False)
        self.W_O = nn.Linear(config.n_heads * self.d_k, config.d_model, bias=False)

        self.rotary = RotaryEmbedding(self.d_k, config.max_seq_len, config.rope_theta)
        self.attn_dropout = nn.Dropout(config.dropout)

    def forward(
        self,
        x: torch.Tensor,
        mask: torch.Tensor | None = None,
        kv_cache: tuple[torch.Tensor, torch.Tensor] | None = None,
    ) -> tuple[torch.Tensor, tuple[torch.Tensor, torch.Tensor]]:
        B, S, _ = x.shape

        Q = self.W_Q(x).view(B, S, self.n_heads, self.d_k).transpose(1, 2)
        K = self.W_K(x).view(B, S, self.n_kv_heads, self.d_k).transpose(1, 2)
        V = self.W_V(x).view(B, S, self.n_kv_heads, self.d_k).transpose(1, 2)

        cos, sin = self.rotary(S)
        Q = apply_rotary_emb(Q, cos, sin)
        K = apply_rotary_emb(K, cos, sin)

        if kv_cache is not None:
            K = torch.cat([kv_cache[0], K], dim=1)
            V = torch.cat([kv_cache[1], V], dim=1)
        new_kv_cache = (K, V)

        if self.n_groups > 1:
            K = K.unsqueeze(2).expand(-1, -1, self.n_groups, -1, -1).reshape(
                B, self.n_heads, -1, self.d_k
            )
            V = V.unsqueeze(2).expand(-1, -1, self.n_groups, -1, -1).reshape(
                B, self.n_heads, -1, self.d_k
            )

        scores = torch.matmul(Q, K.transpose(-2, -1)) / math.sqrt(self.d_k)
        if mask is not None:
            scores = scores.masked_fill(mask == 0, float("-inf"))
        attn_weights = F.softmax(scores, dim=-1)
        attn_weights = self.attn_dropout(attn_weights)

        out = torch.matmul(attn_weights, V)
        out = out.transpose(1, 2).contiguous().view(B, S, -1)
        return self.W_O(out), new_kv_cache


class SwiGLUFFN(nn.Module):
    def __init__(self, config: TransformerConfig):
        super().__init__()
        self.w_up = nn.Linear(config.d_model, config.ff_dim, bias=False)
        self.w_gate = nn.Linear(config.d_model, config.ff_dim, bias=False)
        self.w_down = nn.Linear(config.ff_dim, config.d_model, bias=False)
        self.dropout = nn.Dropout(config.dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.dropout(self.w_down(F.silu(self.w_gate(x)) * self.w_up(x)))


class TransformerBlock(nn.Module):
    def __init__(self, config: TransformerConfig):
        super().__init__()
        self.attn_norm = RMSNorm(config.d_model, config.norm_eps)
        self.attn = GroupedQueryAttention(config)
        self.ffn_norm = RMSNorm(config.d_model, config.norm_eps)
        self.ffn = SwiGLUFFN(config)

    def forward(
        self,
        x: torch.Tensor,
        mask: torch.Tensor | None = None,
        kv_cache: tuple[torch.Tensor, torch.Tensor] | None = None,
    ) -> tuple[torch.Tensor, tuple[torch.Tensor, torch.Tensor]]:
        h, new_kv = self.attn(self.attn_norm(x), mask, kv_cache)
        x = x + h
        x = x + self.ffn(self.ffn_norm(x))
        return x, new_kv


class Transformer(nn.Module):
    def __init__(self, config: TransformerConfig):
        super().__init__()
        self.config = config
        self.tok_emb = nn.Embedding(config.vocab_size, config.d_model)
        self.layers = nn.ModuleList(
            [TransformerBlock(config) for _ in range(config.n_layers)]
        )
        self.final_norm = RMSNorm(config.d_model, config.norm_eps)
        self.lm_head = nn.Linear(config.d_model, config.vocab_size, bias=False)

        self.apply(self._init_weights)
        n_params = sum(p.numel() for p in self.parameters())
        print(f"Model parameters: {n_params / 1e6:.1f}M")

    def _init_weights(self, module: nn.Module):
        if isinstance(module, nn.Linear):
            std = 0.02
            if hasattr(module, "SCALE_INIT"):
                std *= (2 * self.config.n_layers) ** -0.5
            nn.init.normal_(module.weight, mean=0.0, std=std)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            nn.init.normal_(module.weight, mean=0.0, std=0.02)

    def forward(
        self,
        input_ids: torch.Tensor,
        targets: torch.Tensor | None = None,
        kv_caches: list[tuple[torch.Tensor, torch.Tensor] | None] | None = None,
    ) -> dict:
        B, S = input_ids.shape
        x = self.tok_emb(input_ids)

        mask = torch.tril(torch.ones(S, S, device=input_ids.device)).unsqueeze(0).unsqueeze(0)

        new_kv_caches = []
        for i, layer in enumerate(self.layers):
            cache = kv_caches[i] if kv_caches is not None else None
            x, new_kv = layer(x, mask, cache)
            new_kv_caches.append(new_kv)

        x = self.final_norm(x)
        logits = self.lm_head(x)

        loss = None
        if targets is not None:
            loss = F.cross_entropy(
                logits.view(-1, self.config.vocab_size), targets.view(-1)
            )

        return {"logits": logits, "loss": loss, "kv_caches": new_kv_caches}
```

### 6.10.3 GPT Architecture Stack — Full Pipeline

```
  ┌─────────────── GPT Architecture: Full Pipeline ───────────────┐
  │                                                                │
  │  Input: "The cat sat"                                          │
  │     │                                                          │
  │     ▼                                                          │
  │  ┌──────────────────────────────┐                              │
  │  │  Tokenizer (BPE)             │                              │
  │  │  "The" → 464                 │                              │
  │  │  " cat" → 3797               │                              │
  │  │  " sat" → 6451               │                              │
  │  └──────────────┬───────────────┘                              │
  │                 ▼                                              │
  │  ┌──────────────────────────────┐                              │
  │  │  Token Embedding             │                              │
  │  │  464  → [0.2, -0.1, ...]    │                              │
  │  │  3797 → [0.8, 0.3, ...]     │                              │
  │  │  6451 → [-0.5, 0.7, ...]    │   ℝ^{S × d}                  │
  │  └──────────────┬───────────────┘                              │
  │                 ▼                                              │
  │  ┌──────────────────────────────┐                              │
  │  │  + RoPE Positional Encoding  │  (rotary, applied inside     │
  │  │  (no additive embedding)    │   each attention layer)       │
  │  └──────────────┬───────────────┘                              │
  │                 ▼                                              │
  │  ┌══════════════════════════════┐                              │
  │  ║  Transformer Block ×N       ║                              │
  │  ║  ┌────────────────────────┐ ║                              │
  │  ║  │ RMSNorm → GQA Attn    │ ║     ┌─────────────────┐      │
  │  ║  │ + residual → RMSNorm  │ ║     │  Causal Mask      │      │
  │  ║  │ → SwiGLU FFN          │ ║     │  ┌─┬─┬─┬─┐        │      │
  │  ║  │ + residual             │ ║     │  │1│0│0│0│ row0  │      │
  │  ║  └────────────────────────┘ ║     │  │1│1│0│0│ row1  │      │
  │  ╚══════════════════════════════╝     │  │1│1│1│0│ row2  │      │
  │                 ▼                     └─────────────────┘      │
  │  ┌──────────────────────────────┐                              │
  │  │  Final RMSNorm               │                              │
  │  └──────────────┬───────────────┘                              │
  │                 ▼                                              │
  │  ┌──────────────────────────────┐                              │
  │  │  LM Head (Linear)           │                              │
  │  │  d_model → vocab_size       │                              │
  │  │  (often tied with tok_emb)  │                              │
  │  └──────────────┬───────────────┘                              │
  │                 ▼                                              │
  │  ┌──────────────────────────────┐                              │
  │  │  Softmax                     │                              │
  │  │  logits → probabilities      │                              │
  │  │  P("on") = 0.42             │                              │
  │  │  P("down") = 0.11           │                              │
  │  │  ...                         │                              │
  │  └──────────────┬───────────────┘                              │
  │                 ▼                                              │
  │          next token: "on"                                      │
  │          (sample or greedy)                                    │
  └────────────────────────────────────────────────────────────────┘
```

### 6.10.4 Training Objective

The decoder-only transformer is trained with **causal language modeling**:

```
L = -Σ_t log P(x_t | x_{<t}; θ)

For input: [The] [cat] [sat] [on] [the] [mat]
Targets:  [cat] [sat] [on] [the] [mat] [EOS]

Each position predicts the next token given all preceding context,
masked so tokens cannot see the future.
```

### 6.10.5 Key Training Details

| Hyperparameter | Typical Value | Notes |
|---|---|---|
| Learning rate | 3e-4 → 1e-5 (cosine decay) | Warmup 2k steps |
| Batch size | 4M tokens (meta-batch) | Varies by scale |
| Adam β₁, β₂ | 0.9, 0.95 | β₂=0.95 for stability |
| Weight decay | 0.1 | Decoupled from Adam |
| Grad clip | 1.0 | Global norm clipping |
| Dropout | 0.0 (at scale) | Omitted in most large models |
| Init std | 0.02 | Residual scaling at depth |

---

## 6.11 Summary: Architectural Evolution

```
  Timeline of Key Transformer Innovations
  ═══════════════════════════════════════

  2017  ─► Transformer (Vaswani et al.)
         │   Encoder-Decoder, sinusoidal PE, LayerNorm (post-norm)
         │
  2018  ─► BERT / GPT-1
         │   Encoder-only / Decoder-only, learned PE
         │
  2019  ─► GPT-2
         │   Pre-norm, GELU, larger scale
         │
  2020  ─► GPT-3 / Switch Transformer
         │   Few-shot ICL / MoE
         │
  2021  ─► Codex / PaLM
         │   Code generation / parallelism, SwiGLU
         │
  2022  ─► Chinchilla / FlashAttention / MQA
         │   Data vs compute / IO-aware / single KV head
         │
  2023  ─► Llama / Mamba / Mistral / GQA
         │   RoPE / SSMs / sliding window + global / grouped KV
         │
  2024  ─► Llama 3 / DeepSeek-V3 / FlashAttention-3
         │   GQA + MoE / auxiliary-loss-free MoE / Hopper optimized
         │
  2025  ─► Mamba-2 / Hybrid architectures
         │   Structured state space duality / SSM+Attn+MoE combos
```

---

## Further Reading

- **Attention Is All You Need** — Vaswani et al., 2017
- **FlashAttention** — Dao et al., 2022
- **GLU Variants** — Shazeer, 2020
- **RoPE** — Su et al., 2021
- **ALiBi** — Press et al., 2022
- **GQA** — Ainslie et al., 2023
- **Mamba** — Gu & Dao, 2023
- **Mixtral of Experts** — Jiang et al., 2024
- **DeepSeek-V2/V3** — DeepSeek, 2024/2025
- **The Illustrated Transformer** — Jay Alammar (blog)

---

## Real References

1. Vaswani, A., Shazeer, N., Parmar, N., Uszkoreit, J., Jones, L., Gomez, A. N., Kaiser, Ł., & Polosukhin, I. "Attention Is All You Need." *Advances in Neural Information Processing Systems (NeurIPS) 30*, 2017. arXiv:1706.03762. https://arxiv.org/abs/1706.03762

2. Devlin, J., Chang, M.-W., Lee, K., & Toutanova, K. "BERT: Pre-training of Deep Bidirectional Transformers for Language Understanding." *Proceedings of the 2019 Conference of the North American Chapter of the Association for Computational Linguistics (NAACL-HLT)*, 2019. arXiv:1810.04805. https://arxiv.org/abs/1810.04805

3. Radford, A., Wu, J., Child, R., Luan, D., Amodei, D., & Sutskever, I. "Language Models are Unsupervised Multitask Learners." *OpenAI Technical Report*, 2019. https://cdn.openai.com/better-language-models/language_models_are_unsupervised_multitask_learners.pdf

4. Brown, T. B., Mann, B., Ryder, N., Subbiah, M., Kaplan, J., Dhariwal, P., Neelakantan, A., et al. "Language Models are Few-Shot Learners." *Advances in Neural Information Processing Systems (NeurIPS) 33*, 2020. arXiv:2005.14165. https://arxiv.org/abs/2005.14165

5. Touvron, H., Lavril, T., Izacard, G., Martinet, X., Lachaux, M.-A., Lacroix, T., Rozière, B., et al. "LLaMA: Open and Efficient Foundation Language Models." *arXiv preprint arXiv:2302.13971*, 2023. https://arxiv.org/abs/2302.13971

6. Raffel, C., Shazeer, N., Roberts, A., Lee, K., Narang, S., Matena, M., Zhou, Y., Li, W., & Liu, P. J. "Exploring the Limits of Transfer Learning with a Unified Text-to-Text Transformer." *Journal of Machine Learning Research (JMLR) 21*(140):1–67, 2020. arXiv:1910.10683. https://arxiv.org/abs/1910.10683

7. Dao, T., Fu, D., Ermon, S., Rudra, A., & Ré, C. "FlashAttention: Fast and Memory-Efficient Exact Attention with IO-Awareness." *Advances in Neural Information Processing Systems (NeurIPS) 35*, 2022. arXiv:2205.14135. https://arxiv.org/abs/2205.14135

8. Shazeer, N. "Fast Transformer Decoding: One Write-Head is All You Need." *arXiv preprint arXiv:1911.02150*, 2019. https://arxiv.org/abs/1911.02150

9. Fedus, W., Zoph, B., & Shazeer, N. "Switch Transformers: Scaling to Trillion Parameter Models with Simple and Efficient Sparsity." *Journal of Machine Learning Research (JMLR) 23*(120):1–40, 2022. arXiv:2101.03961. https://arxiv.org/abs/2101.03961

10. Su, J., Ahmed, M., Lu, Y., Pan, S., Bo, W., & Liu, K. "RoFormer: Enhanced Transformer with Rotary Position Embedding." *Neurocomputing 568:127063*, 2024 (originally arXiv:2104.09864, 2021). https://arxiv.org/abs/2104.09864

11. Gu, A., & Dao, T. "Mamba: Linear-Time Sequence Modeling with Selective State Spaces." *arXiv preprint arXiv:2312.00752*, 2023. https://arxiv.org/abs/2312.00752

12. Press, O., Smith, N. A., & Lewis, M. "Train Short, Test Long: Attention with Linear Biases Enables Input Length Extrapolation." *Proceedings of the International Conference on Learning Representations (ICLR)*, 2022. arXiv:2108.12409. https://arxiv.org/abs/2108.12409

13. Zhang, B., & Sennrich, R. "Root Mean Square Layer Normalization." *Advances in Neural Information Processing Systems (NeurIPS) 32*, 2019. arXiv:1910.07467. https://arxiv.org/abs/1910.07467

14. Shazeer, N. "GLU Variants Improve Transformer." *arXiv preprint arXiv:2002.05202*, 2020. https://arxiv.org/abs/2002.05202

15. Ainslie, J., Lei, T., & de Vries, H. "GQA: Training Generalized Multi-Query Transformer Models from Multi-Head Checkpoints." *Proceedings of the 2023 Conference on Empirical Methods in Natural Language Processing (EMNLP)*, 2023. arXiv:2305.13245. https://arxiv.org/abs/2305.13245

16. Radford, A., Narasimhan, K., Salimans, T., & Sutskever, I. "Improving Language Understanding by Generative Pre-Training." *OpenAI Technical Report*, 2018. https://cdn.openai.com/research-covers/language-unsupervised/language_understanding_paper.pdf

17. Hendrycks, D., & Gimpel, K. "Gaussian Error Linear Units (GELUs)." *arXiv preprint arXiv:1606.08415*, 2016. https://arxiv.org/abs/1606.08415

18. Ba, J. L., Lei, K., & Hinton, G. E. "Layer Normalization." *arXiv preprint arXiv:1607.06450*, 2016. https://arxiv.org/abs/1607.06450

19. Kitaev, N., Kaiser, Ł., & Levskaya, A. "Reformer: The Efficient Transformer." *Proceedings of the International Conference on Learning Representations (ICLR)*, 2020. arXiv:2001.04028. https://arxiv.org/abs/2001.04028

20. Beltagy, I., Peters, M. E., & Cohan, A. "Longformer: The Long-Document Transformer." *arXiv preprint arXiv:2004.05150*, 2020. https://arxiv.org/abs/2004.05150

21. Choromanski, K., Likhosherstov, V., Dohan, D., Song, X., Gane, A., Sarlós, T., Hawkins, P., et al. "Rethinking Attention with Performers." *International Conference on Learning Representations (ICLR)*, 2021. arXiv:2009.14794. https://arxiv.org/abs/2009.14794

22. Katharopoulos, A., Vyas, A., Pappas, N., & Fleuret, F. "Transformers are RNNs: Fast Autoregressive Transformers with Linear Attention." *Proceedings of the International Conference on Machine Learning (ICML)*, 2020. arXiv:2006.16236. https://arxiv.org/abs/2006.16236

23. Peng, B., Alcaide, E., Anthony, Q., Alberi, M., Grnpcˇar, M., Hrzic, R., et al. "RWKV: Reinventing RNNs for the Transformer Era." *Proceedings of the 2023 Conference on Empirical Methods in Natural Language Processing (EMNLP)*, 2023. arXiv:2305.13048. https://arxiv.org/abs/2305.13048

24. Dao, T. "FlashAttention-2: Faster Attention with Better Parallelism and Work Partitioning." *International Conference on Learning Representations (ICLR)*, 2024. arXiv:2307.08691. https://arxiv.org/abs/2307.08691

25. Shah, J., Yu, B., Dao, T., & Ré, C. "FlashAttention-3: Fast and Approximate Attention with Asynchrony and Low-Precision." *arXiv preprint arXiv:2407.08655*, 2024. https://arxiv.org/abs/2407.08655

26. Lepikhin, D., Lee, H., Xu, Y., Chen, D., Dai, Z., Roy, A., et al. "GShard: Scaling Giant Models with Conditional Computation and Automatic Sharding." *arXiv preprint arXiv:2006.16668*, 2020. https://arxiv.org/abs/2006.16668

27. Jiang, A. Q., Sablayrolles, A., Roux, A., Mensch, A., Savary, G., Bamford, C., et al. "Mixtral of Experts." *arXiv preprint arXiv:2401.04088*, 2024. https://arxiv.org/abs/2401.04088

28. Chowdhery, A., Narang, S., Devlin, J., Bosma, M., Mishra, G., Roberts, A., et al. "PaLM: Scaling Language Modeling with Pathways." *Journal of Machine Learning Research (JMLR) 24*(240):1–113, 2023. arXiv:2204.02311. https://arxiv.org/abs/2204.02311

29. Touvron, H., Martin, L., Stone, K., Albert, P., Almahairi, A., Babaei, Y., et al. "Llama 2: Open Foundation and Fine-Tuned Chat Models." *arXiv preprint arXiv:2307.09288*, 2023. https://arxiv.org/abs/2307.09288

30. Grattafiori, A., Dubey, A., Jauhri, A., Pandey, A., Kadian, A., Al-Dahle, A., et al. "The Llama 3 Herd of Models." *arXiv preprint arXiv:2407.21783*, 2024. https://arxiv.org/abs/2407.21783

31. DeepSeek-AI. "DeepSeek-V2: A Strong, Economical, and Efficient Mixture-of-Experts Language Model." *arXiv preprint arXiv:2405.04434*, 2024. https://arxiv.org/abs/2405.04434

32. DeepSeek-AI. "DeepSeek-V3 Technical Report." *arXiv preprint arXiv:2412.19437*, 2024. https://arxiv.org/abs/2412.19437

33. Gu, A., Goel, K., & Ré, C. "Efficiently Modeling Long Sequences with Structured State Spaces." *Proceedings of the International Conference on Learning Representations (ICLR)*, 2022. arXiv:2111.00396. https://arxiv.org/abs/2111.00396

34. Lieber, O., Lenz, B., Batashvili, A., Shalev, R., et al. "Jamba: A Hybrid Transformer-Mamba Language Model." *arXiv preprint arXiv:2403.19815*, 2024. https://arxiv.org/abs/2403.19815

35. De, S., Smith, S. L., Fernando, A., Botev, A., et al. "Griffin: Mixing Gated Linear Recurrences with Local Attention for Efficient Language Models." *arXiv preprint arXiv:2402.19427*, 2024. https://arxiv.org/abs/2402.19427

36. Shazeer, N., Mirhoseini, A., Maziarz, K., Davis, A., Le, Q. V., Hinton, G. E., & Dean, J. "Outrageously Large Neural Networks: The Sparsely-Gated Mixture-of-Experts Layer." *International Conference on Learning Representations (ICLR)*, 2017. arXiv:1701.06589. https://arxiv.org/abs/1701.06589

37. Zhou, Y., Neiswanger, W., & Ermon, S. "Mixture-of-Experts with Expert Choice Routing." *Advances in Neural Information Processing Systems (NeurIPS) 35*, 2022. arXiv:2202.09368. https://arxiv.org/abs/2202.09368

38. Hoffmann, J., Borgeaud, S., Mensch, A., Buchatskaya, E., Cai, T., Rutherford, E., et al. "Training Compute-Optimal Large Language Models." *arXiv preprint arXiv:2203.15556*, 2022 (Chinchilla). https://arxiv.org/abs/2203.15556

39. Touvron, H., Lavril, T., Izacard, G., Martinet, X., Lachaux, M.-A., Lacroix, T., et al. "LLaMA: Open and Efficient Foundation Language Models." *arXiv preprint arXiv:2302.13971*, 2023. https://arxiv.org/abs/2302.13971

40. Su, J. "Rectified Rotary Position Embedding." *arXiv preprint arXiv:2311.14788*, 2023. https://arxiv.org/abs/2311.14788
## References

- Vaswani, A. et al., "Attention Is All You Need," NeurIPS 2017. https://arxiv.org/abs/1706.03762
- Devlin, J. et al., "BERT: Pre-training of Deep Bidirectional Transformers for Language Understanding," NAACL 2019. https://arxiv.org/abs/1810.04805
- Radford, A. et al., "Language Models are Unsupervised Multitask Learners," OpenAI, 2019.
- Brown, T. et al., "Language Models are Few-Shot Learners," NeurIPS 2020. https://arxiv.org/abs/2005.14165
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
- Touvron, H. et al., "LLaMA: Open and Efficient Foundation Language Models," 2023. https://arxiv.org/abs/2302.13971
- Shazeer, N., "GLU Variants Improve Transformer," 2020. https://arxiv.org/abs/2002.05202
- Su, J. et al., "RoFormer: Enhanced Transformer with Rotary Position Embedding," 2021. https://arxiv.org/abs/2104.09864
- Press, O. et al., "Train Short, Test Long: Attention with Linear Biases," 2021. https://arxiv.org/abs/2108.12409
- Dao, T. et al., "FlashAttention: Fast and Memory-Efficient Exact Attention," NeurIPS 2022. https://arxiv.org/abs/2205.14135
- Shoeybi, M. et al., "Megatron-LM: Training Multi-Billion Parameter Language Models," 2020. https://arxiv.org/abs/1909.08053
- Korthikanti, V. et al., "Reducing Activation Recomputation in Large Transformer Models," 2022. https://arxiv.org/abs/2205.05198
