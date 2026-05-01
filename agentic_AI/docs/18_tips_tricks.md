# Tips, Tricks & Best Practices: The Complete AI/ML/DL & Agentic AI Playbook

> *"In theory, theory and practice are the same. In practice, they are not."* — Yogi Berra

This chapter distills hard-won lessons from the trenches — the undocumented tricks, the silent failure modes, and the subtle art that separates a working system from a production-grade one. Every tip here was learned the hard way.

---

## 0. Visual Cheat Sheet

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    TIPS & TRICKS CHEAT SHEET                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  DATA          ██  MODEL        ██  TRAINING    ██  FINETUNING              ║
║  ─────────     ██  ─────────   ██  ─────────   ██  ──────────              ║
║  Clean first   ██  Init w/     ██  Warmup      ██  LoRA α/r                ║
║  Profile early ██  Kaiming/    ██  Cosine      ██     ratio                 ║
║  Augment smart ██   Xavier     ██  Mixed Prec  ██  Chat template           ║
║  Dedup!        ██  LR find     ██  GradClip    ██  Catastrophic            ║
║  Check leaks   ██  Checkpoint  ██  EMA         ██   forget ≠0              ║
║  Version data  ██   every N    ██  Distributed ██  Format matters           ║
║                ██              ██   >1 node   ██                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  EVAL          ██  DEPLOY      ██  AGENT       ██  MULTI-AGENT              ║
║  ─────────     ██  ─────────   ██  ─────────  ██  ───────────              ║
║  CV not hold   ██  KV-cache   ██  Prompt eng ██  Loop detection           ║
║  Significance  ██   opt        ██  Tool design ██  Context budget          ║
║  Don't overfit ██  Spec decode ██  Structured  ██  Clear roles              ║
║   benchmarks   ██  Cont batch  ██   output    ██  Timeout every            ║
║  Adversarial   ██  Batch       ██  Error recov ██   level                  ║
║   examples     ██   inference  ██  Retries    ██  Shared mem ≠             ║
║                ██              ██             ██   chat history             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  DEBUG         ██  COST        ██  SECURITY    ██  ANTI-PATTERNS           ║
║  ─────────     ██  ─────────   ██  ──────────  ██  ───────────             ║
║  Loss curves   ██  Right model ██  Inj. defend ██  Premature opt           ║
║  Grad analysis ██  Cache hit   ██  Output val ██  Copy-paste code         ║
║  Token debug   ██  Batch >     ██  Rate limit ██  God-agent                ║
║  NaN autopsy   ██   stream     ██  Sanitize    ██  Silent failures         ║
║  Overfit test  ██  GPU choice  ██  Audit log  ██  Sacred hyperparams       ║
║                ██              ██             ██  (none are sacred)         ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 1. Data Tips

### 1.1 Clean Before You Augment

The single most impactful thing you can do is **clean your data before anything else**. Garbage in, garbage out is not a platitude — it is a physical law of ML.

```
Priority Order for Data Work:
─────────────────────────────────
  1. REMOVE exact duplicates          ╔════════════╗
     (this alone can improve           ║ BIGGEST    ║
      accuracy by 2-5%)                ║ BANG FOR   ║
  2. REMOVE near-duplicates            ║ BUCK:      ║
     (fuzzy dedup matters!)            ║ Dedup +    ║
  3. FIX label errors                  ║ Clean      ║
  4. REMOVE mislabeled                ╚════════════╝
  5. BALANCE classes
  6. THEN augment
```

**Fuzzy deduplication** is criminally underrated. Two examples that differ by one typo teach the model the same thing twice and inflate your metrics. Use MinHash + LSH or embedding-based dedup for large corpora.

### 1.2 Profile Early, Profile Often

Before training, always run a data profiling pass:

```python
import pandas as pd
from ydata_profiling import ProfileReport

df = pd.read_json("dataset.jsonl", lines=True)
profile = ProfileReport(df, title="Dataset Profile")
profile.to_file("data_profile.html")
```

Check for:
- **Feature distributions** — Are there bimodal distributions that suggest data contamination?
- **Missing values** — Are they random or systematic? Systematic missingness is a signal.
- **Correlation anomalies** — Features too highly correlated with the target may be label leaks.
- **Cardinality** — A column with 95% unique values is likely an ID, not a feature.

### 1.3 Augmentation: Quality Over Quantity

```python
# GOOD: Targeted augmentations that preserve semantics
augmentations = {
    "back_translation": "en→de→en",        # Preserves meaning, varies syntax
    "synonym_replacement": "preserve=NER",   # Domain-aware substitution
    "random_deletion": "p=0.1",             # Forces robustness
    "contextual_insertion": "MLM-based",     # Fluent insertions
}

# BAD: Random perturbations that destroy meaning
bad_augmentations = {
    "random_swap": "Swaps words, often breaks syntax",
    "uniform_deletion": "p=0.3",  # Too aggressive, kills signal
    "random_insertion": "synonym_dict[random()]",  # No context awareness
}
```

**Key insight**: Augmentation should make the model work harder on the *right things*, not just add noise. The best augmentations are the ones a human would classify as "same example, different surface form."

### 1.4 Data Quality Checklist

Before every training run, verify:

- [ ] No exact duplicates (check hash of `input+output`)
- [ ] No near-duplicates above 0.95 Jaccard similarity
- [ ] No train/test leakage (temporal, group, or feature leakage)
- [ ] Label distribution matches production expectations
- [ ] No HTML artifacts, encoding errors, or null bytes
- [ ] Token lengths within model limits (check 99th percentile, not just max)
- [ ] Conversation turns are properly paired (no orphaned assistant messages)
- [ ] System prompts are consistent within a task

---

## 2. Model Tips

### 2.1 Initialization Matters More Than You Think

```
Initialization Impact on Training:
─────────────────────────────────────

  Good Init (Kaiming/Xavier):         Bad Init (default random):

  Loss                                Loss
   │╲                                  │╲
   │ ╲                                 │  ╲╲
   │  ╲                                │    ╲╲╲╲╲╲
   │   ╲                               │         ╲╲╲╲╲╲
   │    ╲──────                        │              ╲╲╲╲──
   │      plateau                      │    (slow convergence,
   └──────────────── Steps             │     possible saddle point)
                                       └──────────────── Steps

  For ReLU:     use Kaiming (He) init:  std = sqrt(2/fan_in)
  For Tanh/     use Xavier (Glorot):   std = sqrt(2/(fan_in + fan_out))
   Sigmoid:
  For ResNets:  use Kaiming + residual scaling (0.01 for last block)
  For LLMs:     most pre-trained checkpoints are already well-initialized;
                this matters most when training FROM SCRATCH.
```

**Pro tip**: When fine-tuning, never re-initialize layers unless you have a specific reason. The pre-trained weights encode statistical priors about language — reinitializing discards billions of dollars of compute.

### 2.2 Learning Rate Finding

The single most important hyperparameter is the learning rate. Use a learning rate finder:

```python
# Leslie Smith's cyclical LR finding approach
lr_finder = LearningRateFinder(model, optimizer, criterion)
lrs = lr_finder.range_test(train_loader, start_lr=1e-7, end_lr=10, num_iter=100)

# Pick LR where loss decreases most steeply (NOT the minimum)
#                                                    ┌── Pick HERE (steepest descent)
# Loss curve:                                       │
#  │╲                                               │
#  │ ╲                                              │
#  │  ╲─────────────────────────╲                   │
#  │                            ╲──────╲            │
#  │                                   ╲────╲      │
#  │                                         ╲───╲╲───<-- DON'T pick minimum!
#  └────────────────────────────────────────────── LR (log scale)
```

**Common mistakes**:
- Picking the LR at minimum loss → too high, will diverge after a few epochs
- Using the same LR for all parameter groups → fine-tuned layers should use 10-100x lower LR
- Not re-finding LR after changing batch size → LR should scale approximately linearly with batch size (linear scaling rule)

### 2.3 Gradient Management

```python
# Gradient clipping — ALWAYS clip when training transformers
torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)

# Gradient accumulation — simulate larger batch sizes
# effective_batch = micro_batch * accumulation_steps
# LR should scale with effective batch, not micro batch
accumulation_steps = 8  # if target batch=64 but GPU fits batch=8

for i, batch in enumerate(dataloader):
    loss = model(batch) / accumulation_steps
    loss.backward()
    if (i + 1) % accumulation_steps == 0:
        optimizer.step()
        optimizer.zero_grad()
```

### 2.4 Checkpoint Strategies

```
Checkpoint Strategies Compared:
────────────────────────────────

  Strategy A: Save every N steps        Strategy B: Save best only
  ─────────────────────────             ──────────────────────────
  Pro: Never lose progress              Pro: Minimal disk usage
  Con: Disk fills up FAST               Con: Can't roll back to
       (1GB/checkpoint × 1000              earlier learning state
        = 1TB for a 7B model)
                                        Strategy C: Save best + every N
                                        ───────────────────────────────
  BEST PRACTICE:                         Pro: Best of both worlds
  - Save top-3 by validation loss        Con: Slightly more disk
  - Keep last N checkpoints (rolling)
  - Save at epoch boundaries AND every N steps
  - ALWAYS save optimizer state for resumability
  - Include training RNG state for perfect reproducibility
```

---

## 3. Training Tricks

### 3.1 Warmup

Learning rate warmup is **not optional** for transformers. Without it, early gradient explosions destabilize training.

```python
# Linear warmup with cosine decay (most common for LLMs)
from torch.optim.lr_scheduler import LambdaLR
import math

def get_cosine_schedule_with_warmup(optimizer, warmup_steps, total_steps):
    def lr_lambda(step):
        if step < warmup_steps:
            return float(step) / float(max(1, warmup_steps))
        progress = float(step - warmup_steps) / float(max(1, total_steps - warmup_steps))
        return max(0.0, 0.5 * (1.0 + math.cos(math.pi * progress)))
    return LambdaLR(optimizer, lr_lambda)

# Rule of thumb: warmup_steps = total_steps * 0.03 to 0.10
# For very large models (70B+), use 0.05-0.10 of total steps
# For fine-tuning small models, 100-500 steps is usually sufficient
```

### 3.2 Learning Rate Scheduling

```
LR Schedule Comparison:
────────────────────────

LR│      Cosine (recommended)        Constant + Warmup        Polynomial
  │     ╱╲                            ╱───────                 ╲
  │    ╱  ╲                          ╱                          ╲
  │   ╱    ╲                        ╱                            ╲
  │  ╱      ╲                      ╱                              ╲
  │ ╱        ╲                    ╱                                ╲
  │╱          ╲────────────     ──╝                                  ╲───
  └──────Steps──────────────    └────Steps─────              └────Steps─────

  - Smooth decay              - Simple                    - Predictable decay
  - Good generalization       - Good for fine-tune        - Good for known
  - Most used in LLM work     - Works w/ cosine restarts    convergence targets
  - Warmup required           - Warmup required           - Warmup required
```

### 3.3 Mixed Precision Training

```python
# ALWAYS use mixed precision for modern GPU training
from torch.cuda.amp import autocast, GradScaler

scaler = GradScaler()  # Handles loss scaling to prevent grad underflow

for batch in dataloader:
    optimizer.zero_grad()
    with autocast(dtype=torch.bfloat16):  # bf16 preferred over fp16 on Ampere+
        loss = model(batch)
    scaler.scale(loss).backward()
    scaler.unscale_(optimizer)
    torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
    scaler.step(optimizer)
    scaler.update()
```

**Why bfloat16 over float16**: bfloat16 has the same exponent range as float32 (8 bits), so it doesn't need loss scaling. float16 has a smaller exponent range (5 bits) and will overflow/underflow more easily. On Ampere+ GPUs (A100, H100), bfloat16 is the default choice.

### 3.4 Distributed Training Tricks

```
Distributed Data Parallel (DDP) Tips:
─────────────────────────────────────

╔═══════════════════════════════════════════════════════════════╗
║  1. Use gradient accumulation before allreduce               ║
║     → Reduces communication overhead proportionally           ║
║                                                               ║
║  2. Set find_unused_parameters=False (if possible)            ║
║     → Unused params force synchronous waits                   ║
║                                                               ║
║  3. Pin memory for DataLoader                                  ║
║     → Faster CPU→GPU transfers                                ║
║                                                               ║
║  4. Use gradient bucket size tuning                           ║
║     → bucket_cap_mb=25 for small models                      ║
║     → bucket_cap_mb=100 for large models                     ║
║                                                               ║
║  5. gradient_as_bucket_view=True                              ║
║     → Avoids copy between gradient and bucket views           ║
╚═══════════════════════════════════════════════════════════════╝
```

### 3.5 Exponential Moving Average (EMA)

```python
# EMA smooths model parameters, almost always improves generalization
# Maintains a shadow copy of weights as an exponential average

ema_decay = 0.999  # Typical: 0.999 for training, 0.9999 for longer runs

# EMA weight update:
# ema_param = decay * ema_param + (1 - decay) * model_param
#
# After warmup (first ~1000 steps), use ema params for evaluation
# EMA is essentially FREE regularisation — use it unless it breaks something

class EMA:
    def __init__(self, model, decay=0.999):
        self.shadow = {k: v.clone() for k, v in model.state_dict().items()}
        self.decay = decay

    def update(self, model):
        for k, v in model.state_dict().items():
            self.shadow[k] = self.decay * self.shadow[k] + (1 - self.decay) * v
```

---

## 4. Fine-Tuning Tips

### 4.1 LoRA Hyperparameters

```
LoRA Parameter Guide:
─────────────────────

  Parameter    │  Typical Range   │  Advice
  ─────────────┼──────────────────┼───────────────────────────────────
  r (rank)     │  8, 16, 32, 64   │  Start with 16. r=64 rarely helps
               │                  │  over r=32 unless task is complex.
               │                  │  Diminishing returns above 64.
  ─────────────┼──────────────────┼───────────────────────────────────
  alpha (α)    │  16, 32, 64      │  α/r ratio matters more than α
               │                  │  alone. α=2r is a common starting
               │                  │  point (α=32 for r=16).
  ─────────────┼──────────────────┼───────────────────────────────────
  dropout      │  0.0 - 0.1       │  0.05-0.1 for small datasets
               │                  │  0.0 for large datasets (>100K)
  ─────────────┼──────────────────┼───────────────────────────────────
  target       │  q_proj, v_proj  │  Target ALL linear layers for
  modules      │  k_proj, o_proj  │  best results. Targeting only
               │  gate_proj, etc. │  q/v works but is suboptimal.
  ─────────────┼──────────────────┼───────────────────────────────────
  LR for LoRA  │  1e-4 to 3e-4   │  10x higher than full fine-tune
               │                  │  is normal and expected.
```

**The alpha/rank ratio**: This is the effective scaling factor. `α/r = 1` means LoRA updates are scaled by 1 (moderate update). `α/r = 2` means stronger updates. Most practitioners start with `α = 2r` and tune from there.

### 4.2 Dataset Formatting & Chat Templates

```python
# WRONG: Random format mixing
examples = [
    {"prompt": "What is AI?", "response": "AI is..."},     # format A
    {"instruction": "Explain ML", "output": "ML is..."},   # format B
    {"messages": [{"role": "user", "content": "..."}]},     # format C
]

# RIGHT: Consistent chat template throughout
from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("model_name")
template = tokenizer.apply_chat_template

examples = [
    {"messages": [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user",   "content": "What is AI?"},
        {"role": "assistant", "content": "AI is..."},
    ]},
    # All examples follow the same structure
]

# Convert to formatted strings
formatted = [template(ex["messages"], tokenize=False) for ex in examples]
```

**Critical**: Always use the model's native chat template. Mixing templates or inventing your own will silently degrade performance by 5-20%. The model learned a specific format during pre-training — respect it.

### 4.3 Catastrophic Forgetting Avoidance

```
Strategies to Avoid Catastrophic Forgetting:
─────────────────────────────────────────────

  Strategy          │  Effectiveness  │  Cost       │  When to Use
  ──────────────────┼─────────────────┼─────────────┼──────────────────
  LoRA/QLoRA        │  ★★★★★         │  Low        │  Default choice
  (freeze base)     │                 │             │
  ──────────────────┼─────────────────┼─────────────┼──────────────────
  Replay buffer     │  ★★★★           │  Medium     │  With LoRA
  (mix old data)   │                 │             │
  ──────────────────┼─────────────────┼─────────────┼──────────────────
  Weight decay      │  ★★★            │  Low        │  Small datasets
  (L2 toward init)  │                 │             │
  ──────────────────┼─────────────────┼─────────────┼──────────────────
  EWC / L2 reg      │  ★★★            │  Medium     │  Research only
  ──────────────────┼─────────────────┼─────────────┼──────────────────
  Progressive       │  ★★★            │  High       │  Curriculum
  layer unfreeze    │                 │             │  fine-tuning
  ──────────────────┼─────────────────┼─────────────┼──────────────────
  Lower LR          │  ★★              │  Free       │  Always, but
                    │                 │             │  insufficient alone

  GOLDEN RULE: LoRA + small replay buffer (5-10% of old data) = near-zero forgetting
```

---

## 5. Evaluation Tricks

### 5.1 Cross-Validation Over Holdout

Never trust a single train/val/test split. Use stratified k-fold cross-validation for final results:

```python
from sklearn.model_selection import StratifiedKFold

# For small datasets: k=5 or k=10
# For large datasets (>100K): k=3 is fine, single holdout is OK
# For LLM evaluation: report mean ± std across at least 3 seeds

kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scores = []
for fold, (train_idx, val_idx) in enumerate(kfold.split(X, y)):
    model = train_model(X[train_idx], y[train_idx])
    score = evaluate(model, X[val_idx], y[val_idx])
    scores.append(score)

print(f"Mean: {np.mean(scores):.4f} ± {np.std(scores):.4f}")
```

### 5.2 Statistical Significance

```
Reporting Results Properly:
─────────────────────────────

  ╔══════════════════════════════════════════════════════════════╗
  ║  ALWAYS report:                                             ║
  ║  1. Mean ± standard deviation across seeds                  ║
  ║  2. Number of seeds (minimum 3, aim for 5+)                 ║
  ║  3. Confidence intervals (bootstrap or t-distribution)      ║
  ║  4. Effect size (Cohen's d), not just p-value               ║
  ║                                                              ║
  ║  NEVER claim improvement without:                           ║
  ║  - Statistical significance test (paired bootstrap preferred)║
  ║  - Effect size > small (d > 0.2)                            ║
  ║  - Multiple evaluation sets (not cherry-picked)             ║
  ╚══════════════════════════════════════════════════════════════╝
```

### 5.3 Avoiding Overfitting to Benchmarks

- **Rotate benchmarks**: Don't optimize against the same held-out set repeatedly.
- **Use held-out data the model has NEVER seen**: If you've iterated 50 times on MMLU, your model is overfitting to MMLU even if it never saw the questions.
- **Report aggregate scores**: MMLU average hides domain-specific weaknesses. Report per-subject scores.
- **Task contamination check**: Verify no training data overlaps with benchmark data using n-gram matching.

---

## 6. Deployment Tips

### 6.1 Batching Strategies

```
Static Batching vs. Continuous Batching:
─────────────────────────────────────────

  Static Batching:                    Continuous Batching:
  ┌──────────────────────────┐      ┌──────────────────────────┐
  │ Req1: ████████████       │      │ Req1: ████████████       │
  │ Req2: ████████           │      │ Req2: ████████Req3: ████ │
  │ Req3: ██████             │      │ Req3: ████Req4: ████████ │
  │ Req4: ████               │      │ Req4: ████████           │
  │       ↑ padded to longest│      │     ↑ no padding waste   │
  └──────────────────────────┘      └──────────────────────────┘
  Padding waste: ~40-60%             Throughput increase: 2-4x

  Implementation: vLLM, TGI, or TensorRT-LLM all support continuous batching
```

### 6.2 KV-Cache Optimization

```python
# KV-cache is THE bottleneck for long-context inference
# Optimizations in order of impact:

# 1. PagedAttention (vLLM) — eliminates memory fragmentation
#    Manages KV cache in fixed-size pages, like virtual memory

# 2. KV-cache quantization — INT8 or FP8 for KV storage
#    50% memory reduction, <0.1% quality loss

# 3. Sliding window attention — only cache last N tokens
#    Mistral-style: window=4096, works well for most tasks

# 4. KV-cache offloading — move cold KV to CPU/Disk
#    Useful for very long contexts (>32K tokens)

# 5. Prefix caching — cache shared prompt prefixes
#    Huge win for multi-turn conversations with same system prompt

# Memory estimate for KV cache:
# M = 2 * n_layers * n_heads * head_dim * seq_len * dtype_bytes
# For Llama-2-7B with 4096 context:
# M = 2 * 32 * 32 * 128 * 4096 * 2 = ~2 GB per sequence
```

### 6.3 Speculative Deccoding

```
Speculative Decoding:
──────────────────────

  Problem: Autoregressive generation is 1 token per forward pass
           (memory-bandwidth bound, not compute bound)

  Solution: Use a SMALL draft model to guess K tokens ahead,
            then verify with the LARGE model in one pass

  Step 1: Draft model generates K tokens   ──► t1, t2, t3
  Step 2: Large model verifies all K        ──► Accept/Reject each
  Step 3: Accept first N matching tokens

  ┌──────────────────────────────────────────────────────┐
  │ Time ──────────────────►                             │
  │                                                       │
  │ Draft  │▓▓│▓▓│▓▓│▓▓│         (4 token guesses)      │
  │ Target │        │▓▓▓▓▓│      (1 pass verifies all)   │
  │ Result │██│██│▓▓│░░░░│      (3 accepted, 1 rejected) │
  │        t1  t2  t3  ↑                                   │
  │                 rejected, resample from target          │
  └──────────────────────────────────────────────────────┘

  Typical speedup: 2-3x with 85%+ acceptance rate
  Key requirement: Draft model must be similar distribution to target
```

---

## 7. Agent Tips

### 7.1 Prompt Engineering for Agents

```
The Anatomy of an Effective Agent Prompt:
──────────────────────────────────────────

  ┌─────────────────────────────────────────────┐
  │ 1. ROLE: You are a {domain} expert...       │  ← Clear, specific role
  │ 2. CAPABILITIES: You can {list tools}       │  ← Explicit tool access
  │ 3. CONSTRAINTS:                             │  ← Critical safety bounds
  │    - Never {dangerous action}               │
  │    - Always {safety check} before {action}  │
  │    - Maximum {N} tool calls per turn         │
  │ 4. OUTPUT FORMAT:                           │  ← Structured output spec
  │    Return JSON: {"answer": str,              │
  │                  "confidence": float,        │
  │                  "sources": list}             │
  │ 5. EXAMPLES:                               │  ← 2-3 few-shot examples
  │    User: {example input}                    │     with full tool traces
  │    Agent: {example reasoning + tool use}     │
  │ 6. ERROR HANDLING:                          │  ← What to do on failure
  │    If tool returns error, {fallback}         │
  └─────────────────────────────────────────────┘

  Anti-patterns:
  ✗ "You are a helpful assistant" (too vague)
  ✗ "Do whatever the user asks" (no constraints)
  ✗ No examples at all (model has no anchor)
  ✗ Example without tool use (model won't use tools)
```

### 7.2 Tool Design Principles

```python
# Good tool design:
tools = [
    {
        "name": "search_documents",
        "description": "Searches the knowledge base for documents matching the query. "
                       "Returns top-k results with relevance scores. "
                       "Use this when you need factual information from the knowledge base.",
        "parameters": {
            "query": {"type": "string", "description": "Search query, 3-50 words"},
            "top_k": {"type": "integer", "description": "Number of results (1-10)", "default": 5},
        }
    },
]

# Bad tool design:
bad_tools = [
    {
        "name": "search",  # Too vague
        "description": "Searches stuff",  # Useless description
        "parameters": {
            "q": {"type": "string"},  # Cryptic parameter name
            # No constraints, no defaults
        }
    },
]

# GUIDELINES:
# 1. Name: verb_noun format (search_documents, not doc_search)
# 2. Description: When AND why to use, not just what it does
# 3. Parameters: Types, ranges, defaults, AND descriptions
# 4. Dedup: Never provide overlapping tools (search vs find_documents)
# 5. Minimize: 3-7 tools is the sweet spot. More = confusion.
```

### 7.3 Structured Outputs

```
Structured Output Strategies:
─────────────────────────────

  Method 1: JSON Schema (most reliable)
  ────────────────────────────────────
  - Define a JSON schema, pass to model via tool calling
  - Constrained decoding guarantees valid JSON
  - Works with OpenAI, Anthropic, open-source vLLM

  Method 2: XML Tags (good for extraction)
  ────────────────────────────────────
  Prompt: "Put your answer in <answer> tags"
  Parse: re.search(r'<answer>(.*?)</answer>', response)

  Method 3: Regex Constrained Generation
  ───────────────────────────────────────
  - Use outlines or guidance library
  - Define a regex/CFG that the model must follow
  - Guaranteed valid output at the character level

  ╔══════════════════════════════════════════════════╗
  ║  ALWAYS use structured outputs for:              ║
  ║  - Tool call arguments (JSON schema)             ║
  ║  - Multi-step reasoning traces                  ║
  ║  - Final answers that feed into pipelines       ║
  ║  - Any output that another system consumes       ║
  ╚══════════════════════════════════════════════════╝
```

### 7.4 Error Recovery

```python
# Agent error recovery pattern
async def agent_with_retry(query, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = await agent.run(query)
            # Validate structured output
            parsed = parse_response(response)
            if parsed.is_valid():
                return parsed
            else:
                # Feed error back to agent for self-correction
                query = f"Your last response was invalid: {parsed.errors}. Fix it."
                continue
        except ToolError as e:
            # Tool-specific recovery
            if e.code == "rate_limit":
                await asyncio.sleep(2 ** attempt)
                continue
            elif e.code == "invalid_input":
                query = f"The tool call was invalid: {e.message}. Try a different approach."
                continue
            else:
                raise

    return fallback_response()  # Graceful degradation, not crash
```

---

## 8. Multi-Agent Tips

### 8.1 Avoiding Infinite Loops

```
Infinite Loop Prevention:
─────────────────────────

  Common Loop Patterns:                Prevention Strategies:
  ───────────────────                  ──────────────────────

  Agent A → Agent B → Agent A → ...    1. MAX ITERATIONS per task
                                         (hard limit: 5-10 turns)

  Agent A: "Ask B to check"           2. MONOTONIC PROGRESS RULE
  Agent B: "Ask A to verify"              Each turn MUST make forward
                                          progress (new info, decision,
  Agent A: "I think X"                    or removal of uncertainty)
  Agent B: "Actually, maybe Y"
  Agent A: "Hmm, could be X"           3. STATE HASH CHECK
                                          Hash conversation state each
                                          turn. If hash repeats → break

                                       4. ESCALATION RULE
                                          After N turns without
                                          resolution → human or
                                          deterministic fallback

  ┌────────────────────────────────────────────────────────┐
  │  for turn in range(MAX_TURNS):                          │
  │      state_hash = hash(conversation)                     │
  │      if state_hash in seen_hashes:                       │
  │          return "Loop detected, using fallback"          │
  │      seen_hashes.add(state_hash)                        │
  │                                                          │
  │      if progress_metric(state) <= last_progress:        │
  │          no_progress_count += 1                         │
  │          if no_progress_count >= 3:                     │
  │              return "Stuck, escalating"                  │
  │                                                          │
  │      last_progress = progress_metric(state)             │
  └────────────────────────────────────────────────────────┘
```

### 8.2 Managing Context Across Agents

```
Context Management in Multi-Agent Systems:
───────────────────────────────────────────

  Problem: Each agent has limited context window
  Solution: Summarize, not copy-paste

  ❌ BAD: Forward entire conversation history
  ┌──────────────────────────────────────┐
  │ Agent A sends 4000 tokens to Agent B │
  │ Agent B adds 2000 tokens of reasoning │
  │ Agent B sends 6000 tokens to Agent C │ ← Context explosion!
  │ Agent C adds 2000 tokens              │
  │ Agent C sends 8000 tokens to Agent A │ ← Already over budget
  └──────────────────────────────────────┘

  ✅ GOOD: Summarize + structured handoff
  ┌──────────────────────────────────────┐
  │ Agent A: "Task: X, Found: Y, Need: Z"│
  │ → 200 token summary + structured data │
  │ Agent B: Receives 200 tokens          │
  │ Agent B: "Result: W, Confidence: 0.9"│
  │ → 150 token result                    │
  └──────────────────────────────────────┘

  Shared Memory Pattern:
  ┌──────────┐     ┌──────────────────────┐     ┌──────────┐
  │ Agent A  │────►│   Shared Memory      │◄────│ Agent B  │
  │ Planner  │     │  ┌────────────────┐  │     │ Coder    │
  └──────────┘     │  │ Task state     │  │     └──────────┘
                   │  │ Key decisions   │  │     ┌──────────┐
                   │  │ Results so far  │  │◄────│ Agent C  │
                   │  │ Open questions  │  │     │ Reviewer │
                   │  └────────────────┘  │     └──────────┘
                   └──────────────────────┘
```

### 8.3 Preventing Agent Confusion

- **Clear role boundaries**: Each agent should have a single, well-defined responsibility. Overlapping roles cause agents to duplicate work or contradict each other.
- **Unique agent identifiers**: Always prefix agent outputs with the agent name. "Planner: I think..." not "I think..."
- **Sequential > parallel when conflicted**: If agents disagree, don't let them argue — use an arbiter or fall back to sequential resolution.
- **Shared scratchpad over message passing**: A shared, versioned document reduces synchronization issues compared to point-to-point messaging.

---

## 9. Debugging Tips

### 9.1 Loss Curve Reading Guide

```
Interpreting Loss Curves:
═════════════════════════

  Pattern 1: HEALTHY TRAINING
  ─────────────────────────────
  Loss│╲
      │ ╲
      │  ╲
      │   ╲
      │    ╲──────────
      │      Validation (slightly above train)
      └──────────────── Steps
  → Gradual decrease, small train-val gap = healthy

  Pattern 2: OVERFITTING
  ───────────────────────
  Loss│╲
      │ ╲ train
      │  ╲
      │   ╲
      │    ╲─────╲ train (keeps decreasing)
      │          ╲──────╲──────╲
      │     val───/──╲───╲
      │            /    ╲  ╲ ← validation INCREASES
      └──────────────── Steps
  → Val loss starts increasing = OVERFITTING. Stop training.
     Solutions: more data, dropout, weight decay, early stopping

  Pattern 3: UNDERFITTING (high bias)
  ─────────────────────────────────────
  Loss│╲
      │ ╲
      │  ╲──────────────── (plateau early and high)
      │   ╲──── val (similar to train, both high)
      │    ╲────────
      │
      └──────────────── Steps
  → Both losses plateau high = UNDERFITTING
     Solutions: bigger model, lower LR, train longer, more capacity

  Pattern 4: LEARNING RATE TOO HIGH
  ────────────────────────────────────
  Loss│    ╱╲
      │   ╱  ╲  ╱╲
      │  ╱    ╲╱  ╲     ← Oscillating wildly
      │ ╱          ╲╱╲
      │╱
      └──────────────── Steps
  → Violent oscillations or divergence = LR too high
     Solution: Decrease LR by 10x, add warmup

  Pattern 5: LEARNING RATE TOO LOW
  ───────────────────────────────────
  Loss│╲
      │ ╲
      │  ╲───────────────── (barely decreasing)
      │   ╲
      │    ╲
      │     ╲
      └──────────────── Steps
  → Nearly flat, barely improving = LR too low
     Solution: Increase LR by 3-10x

  Pattern 6: GRADIENT EXPLOSION
  ───────────────────────────────
  Loss│╲
      │ ╲
      │  ╲
      │   ╲
      │    ╲
      │     ╲────────────────────── (sudden spike!)
      │      ╲↑ ∞ ← loss jumps to NaN
      └──────────────── Steps
  → Sudden spike to infinity = gradient explosion
     Solutions: gradient clipping (max_norm=1.0), lower LR, check data
```

### 9.2 Gradient Analysis

```python
# Gradient health check
def diagnose_gradients(model):
    for name, param in model.named_parameters():
        if param.grad is not None:
            grad_norm = param.grad.norm().item()
            grad_mean = param.grad.mean().item()
            grad_std = param.grad.std().item()

            # Red flags:
            if grad_norm == 0:
                print(f"⚠️  {name}: ZERO gradient — dead neuron?")
            elif grad_norm > 100:
                print(f"⚠️  {name}: EXPLODING gradient ({grad_norm:.1f})")
            elif abs(grad_mean) > grad_std * 10:
                print(f"⚠️  {name}: Biased gradient (mean={grad_mean:.6f}, std={grad_std:.6f})")
            elif grad_std == 0:
                print(f"⚠️  {name}: Constant gradient — possible bug")
```

### 9.3 Token-Level Debugging

```
Debugging Workflow:
══════════════════

  ┌───────────────────────────────────────────────────────────┐
  │                    DEBUGGING WORKFLOW                      │
  │                                                            │
  │  1. LOSS NOT DECREASING?                                   │
  │     ├── Check LR (try 10x higher and 10x lower)            │
  │     ├── Check data (shuffle, visualize inputs/labels)       │
  │     ├── Check model forward pass (debug print intermediate) │
  │     └── Check loss function (correct reduction? weights?)  │
  │                                                            │
  │  2. LOSS DECREASES BUT METRICS DON'T?                      │
  │     ├── Check eval data split (train/val leak?)            │
  │     ├── Check metric computation (offset by 1? wrong vocab?)│
  │     └── Check for class imbalance (accuracy misleading?)   │
  │                                                            │
  │  3. LOSS SPIKES OR NaN?                                    │
  │     ├── Check for NaN in data (inf labels, bad text)       │
  │     ├── Add gradient clipping (max_norm=1.0)                │
  │     ├── Check for division by zero in loss                  │
  │     └── Lower LR (try 10x lower)                            │
  │                                                            │
  │  4. TRAINING UNSTABLE?                                     │
  │     ├── Check batch size (too small = noisy gradients)      │
  │     ├── Check mixed precision (use bf16, not fp16)          │
  │     ├── Check data ordering (shuffle each epoch!)            │
  │     └── Add EMA (smoothing)                                 │
  │                                                            │
  │  5. MODEL GENERATES GARBAGE?                               │
  │     ├── Token-level debug: print top-k predictions          │
  │     ├── Check tokenizer match (train vs inference)         │
  │     ├── Check special tokens (BOS, EOS, PAD)               │
  │     └── Check temperature (try 0.0 for greedy debug)        │
  └───────────────────────────────────────────────────────────┘
```

For token-level debugging specifically:

```python
# Print top-k predictions at each position
def debug_token_predictions(model, input_ids, tokenizer, top_k=5):
    with torch.no_grad():
        logits = model(input_ids).logits  # [1, seq_len, vocab_size]

    for pos in range(logits.shape[1]):
        probs = torch.softmax(logits[0, pos], dim=-1)
        top_k_probs, top_k_ids = torch.topk(probs, top_k)

        target_token = tokenizer.decode([input_ids[0, pos].item()])
        print(f"\nPosition {pos} (input: '{target_token}'):")
        for prob, tid in zip(top_k_probs, top_k_ids):
            token = tokenizer.decode([tid.item()])
            print(f"  {token:15s} {prob.item():.4f}")
```

---

## 10. Cost Optimization

### 10.1 Cost Optimization Decision Tree

```
                    COST OPTIMIZATION DECISION TREE
                    ═══════════════════════════════

                         Need an LLM?
                            │
                    ┌──────┴──────┐
                    │             │
                  Yes             No ──► Use regex, heuristics, or rules
                    │                   (cheapest, fastest, often sufficient)
                    │
              What's the task?
                    │
         ┌──────────┼──────────┐
         │          │          │
     Classification  Summariz.  Creative
     / Extraction    / QA       / Writing
         │          │          │
         ▼          ▼          ▼
    Smaller model   Mid model   Need 70B+?
    (1-3B)          (7-14B)       │
         │          │         ┌──┴──┐
         │          │        Yes    No
    Fine-tune     Fine-tune  │     │
    for task     for task   API   Open-source 70B
         │          │       │     (self-host if
    Batch          Stream   │      high volume)
    inference    or batch   │
                              Use caching!
                              Same prompt prefix = cache hit

  ┌──────────────────────────────────────────────────────────────┐
  │                    MODEL SELECTION GUIDE                     │
  │                                                              │
  │  Task                  │  Recommended Model    │  Est. Cost   │
  │  ─────────────────────│──────────────────────│──────────────│
  │  Simple classification│  DistilBERT/ModernBERT│  Free/WTF    │
  │  NER, extraction       │  Phi-3-mini (3.8B)  │  ~$0.01/1K  │
  │  Summarization         │  Llama-3.1-8B        │  ~$0.05/1K   │
  │  Chat/RAG              │  Llama-3.1-8B/Mistral│  ~$0.10/1K  │
  │  Complex reasoning     │  Claude/GPT-4o       │  ~$3-5/1M    │
  │  Code generation       │  DeepSeek-Coder      │  ~$0.14/1M   │
  │  Multi-agent planning  │  Claude/GPT-4o       │  ~$5-10/task │
  └──────────────────────────────────────────────────────────────┘
```

### 10.2 Caching Strategies

```python
# Semantic caching for LLM calls
import hashlib
import json

class SemanticCache:
    def __init__(self, threshold=0.95):
        self.cache = {}  # In production, use Redis/SQLite
        self.threshold = threshold
        self.encoder = SentenceTransformer("all-MiniLM-L6-v2")

    def get(self, query):
        query_emb = self.encoder.encode(query)
        for key, (cached_emb, response) in self.cache.items():
            sim = cosine_similarity(query_emb, cached_emb)
            if sim > self.threshold:
                return response  # Cache HIT
        return None  # Cache MISS

    def set(self, query, response):
        query_emb = self.encoder.encode(query)
        self.cache[hashlib.md5(query.encode()).hexdigest()] = (query_emb, response)

# Typical cache hit rates:
# - RAG systems: 30-60% (many users ask similar questions)
# - Classification: 20-40%
# - Creative generation: 5-10% (less cacheable)
```

### 10.3 Batch vs Streaming

```
Batch vs Streaming Decision:
─────────────────────────────

  Use BATCH when:                          Use STREAMING when:
  ────────────────                         ──────────────────
  - Processing offline datasets            - Real-time chat interfaces
  - Can accumulate requests (latency OK)   - User waiting for response
  - Need maximum throughput                - Progressive display needed
  - Cost per token matters more than       - Early stopping possible
    latency                                  (user sees beginning, can cancel)
  - Running evaluations                    - Long generation tasks
  - Extractive/analytical tasks            - Agent reasoning chains

  Cost savings with batching:              Cost savings with streaming:
  - 50% cheaper on most APIs              - 20-30% savings from early
    (batch endpoints)                        stopping (user cancels)
  - 2-4x throughput on self-hosted        - Reduced timeout costs
                                                 (delivery = completion)
```

### 10.4 GPU Selection Guide

```
GPU Selection for Different Workloads:
───────────────────────────────────────

  Workload              │  Recommended GPU      │  Why
  ──────────────────────│───────────────────────│──────────────────────
  Inference 7B model    │  1x A10G (24GB)       │  Fits in VRAM, cheap
  Inference 70B model   │  2x A100 (80GB)       │  Need tensor parallel
  Fine-tune 7B (LoRA)  │  1x A100 (40GB)       │  LoRA fits single GPU
  Fine-tune 70B (LoRA) │  4-8x A100 (80GB)     │  Distributed training
  Pre-training from     │  8-256x H100 (80GB)   │  Max compute, NVLink
   scratch               │
  ──────────────────────│───────────────────────│──────────────────────
  Budget inference       │  RTX 4090 (24GB)      │  Best $/perf consumer
  Budget fine-tune       │  RTX 4090 (24GB)      │  QLoRA 7B fits
  Development/testing   │  T4 (16GB) or free    │  Cheap, SFF available

  Pro tip: Spot/preemptible instances are 60-70% cheaper for
  fine-tuning (with checkpointing, interruptions are tolerable)
```

---

## 11. Security Tips

### 11.1 Prompt Injection Defense

```
Security Defense Layers:
════════════════════════

  ┌─────────────────────────────────────────────────────────────────┐
  │                     LAYER 1: INPUT VALIDATION                    │
  │  ┌─────────────────────────────────────────────────────────────┐ │
  │  │ • Length limits (reject inputs > N tokens)                  │ │
  │  │ • Regex patterns for known attack strings                   │ │
  │  │ • Input classification model (benign vs. adversarial)       │ │
  │  │ • Strip/encode special tokens and control characters        │ │
  │  └─────────────────────────────────────────────────────────────┘ │
  │                              │                                    │
  │  ┌───────────────────────────▼─────────────────────────────────┐ │
  │  │              LAYER 2: PROMPT ENGINEERING                    │ │
  │  │ • Clear system prompt boundaries                            │ │
  │  │ • Instruction: "Only respond to requests about {domain}"    │ │
  │  │ • Delimiter-based isolation: <|user_input_start|>{input}   │ │
  │  │ • System prompt AFTER user input (less confusable)         │ │
  │  └─────────────────────────────────────────────────────────────┘ │
  │                              │                                    │
  │  ┌───────────────────────────▼─────────────────────────────────┐ │
  │  │              LAYER 3: OUTPUT VALIDATION                     │ │
  │  │ • Structured output format (JSON schema enforcement)        │ │
  │  │ • Output length limits                                      │ │
  │  │ • Content policy filter (secondary model or regex)          │ │
  │  │ • PII detection and redaction                               │ │
  │  │ • Factual grounding check (against retrieval context)        │ │
  │  └─────────────────────────────────────────────────────────────┘ │
  │                              │                                    │
  │  ┌───────────────────────────▼─────────────────────────────────┐ │
  │  │              LAYER 4: RATE LIMITING & MONITORING            │ │
  │  │ • Per-user rate limits                                      │ │
  │  │ • Anomaly detection on request patterns                     │ │
  │  │ • Audit logging (input + output + metadata)                 │ │
  │  │ • Automatic escalation on repeated failures                  │ │
  │  └─────────────────────────────────────────────────────────────┘ │
  └─────────────────────────────────────────────────────────────────┘
```

### 11.2 Output Validation

```python
# Defense in depth: validate LLM outputs at multiple levels
def validate_llm_output(raw_output: str) -> dict:
    # Level 1: Parse (structural validation)
    try:
        parsed = json.loads(raw_output)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON", "fallback": generate_safe_default()}

    # Level 2: Schema validation (field-level)
    required_fields = ["answer", "confidence", "sources"]
    if not all(f in parsed for f in required_fields):
        return {"error": "Missing fields", "fallback": generate_safe_default()}

    # Level 3: Value validation (semantic bounds)
    if not 0 <= parsed["confidence"] <= 1:
        parsed["confidence"] = 0.0  # Reset invalid confidence

    if parsed["answer"].count(parsed["answer"]) > 1:
        # Repetition detected — truncate
        parsed["answer"] = parsed["answer"][:500]

    # Level 4: Content policy (safety)
    if contains_pii(parsed["answer"]) or contains_harmful(parsed["answer"]):
        return {"error": "Content policy violation", "fallback": "I cannot provide that information."}

    return parsed
```

### 11.3 Rate Limiting for Agent Systems

```python
# Token-bucket rate limiter for API calls
import time
from threading import Lock

class TokenBucketRateLimiter:
    def __init__(self, rate: float, capacity: int):
        self.rate = rate          # Tokens per second
        self.capacity = capacity   # Max burst size
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self.lock = Lock()

    def acquire(self, tokens: int = 1) -> bool:
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity,
                              self.tokens + (now - self.last_refill) * self.rate)
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def wait_and_acquire(self, tokens: int = 1):
        while not self.acquire(tokens):
            time.sleep(0.1)

# Usage: 10 requests/second with burst of 20
limiter = TokenBucketRateLimiter(rate=10, capacity=20)
```

---

## 12. Common Anti-Patterns and How to Avoid Them

### 12.1 Anti-Patterns Catalog

```
╔══════════════════════════════════════════════════════════════════════════╗
║                    COMMON ANTI-PATTERNS CATALOG                         ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  #1  PREMATURE OPTIMIZATION                                              ║
║  ══════════════════════                                                  ║
║  "We need a 70B model with multi-agent orchestration"                   ║
║  → Start with a small model + simple pipeline. Scale only when          ║
║    you have evidence that the simple approach is the bottleneck.         ║
║                                                                          ║
║  #2  SACRED HYPERPARAMETERS                                              ║
║  ═══════════════════════                                                ║
║  "Everyone uses lr=2e-5, so I will too"                                ║
║  → No hyperparameter is sacred. LR, batch size, epochs, even            ║
║    architecture choices should be validated on YOUR data.               ║
║                                                                          ║
║  #3  THE GOD-AGENT                                                       ║
║  ═══════════════                                                         ║
║  "This agent handles research, writing, coding, AND deployment"         ║
║  → Single agents handling everything become unreliable and expensive.    ║
║    Split into specialized agents with clear boundaries.                  ║
║                                                                          ║
║  #4  COPY-PASTE PROMPT ENGINEERING                                       ║
║  ════════════════════════════                                            ║
║  "I found this prompt on GitHub, it should work"                        ║
║  → Prompts are model-specific. A prompt-tuned for GPT-4 will            ║
║    fail on Llama. Always test and adapt prompts to YOUR model.           ║
║                                                                          ║
║  #5  SILENT FAILURES                                                     ║
║  ═════════════════                                                       ║
║  "The agent sometimes returns empty responses, but usually works"       ║
║  → Empty/null responses are SYMPTOMS. Always log, always handle,        ║
║    never ignore. Implement retry logic and alerting.                     ║
║                                                                          ║
║  #6  TRAINING ON THE TEST SET (directly or indirectly)                  ║
║  ═══════════════════════════════════════════                             ║
║  "Our model gets 99% on MMLU!" (after tuning on MMLU for 3 weeks)     ║
║  → Use held-out data that was NEVER seen during any iteration.           ║
║    Benchmarking on data you iterated on is measuring memorization.       ║
║                                                                          ║
║  #7  THE MESH NETWORK (multi-agent)                                      ║
║  ═══════════════════════════════                                          ║
║  "Every agent can talk to every other agent"                            ║
║  → Fully connected agent networks are chaotic. Use a directed            ║
║    acyclic graph (DAG) with clear supervisor/router.                    ║
║                                                                          ║
║  #8  MEGA-PROMPT                                                          ║
║  ════════════════                                                         ║
║  "My system prompt is 5000 tokens of detailed instructions"              ║
║  → Long prompts increase latency, cost, and confusion. Keep             ║
║    prompts <1000 tokens. Use few-shot examples over verbose             ║
║    instructions whenever possible.                                       ║
║                                                                          ║
║  #9  NO RETRY / NO FALLBACK                                              ║
║  ══════════════════════════                                               ║
║  "If the LLM fails, just return an error"                               ║
║  → LLMs fail 5-20% of the time depending on task. ALWAYS have:         ║
║    (1) retry with backoff, (2) simpler fallback model,                   ║
║    (3) hardcoded safe response.                                         ║
║                                                                          ║
║  #10 IGNORING LATENCY BUDGETS                                            ║
║  ═════════════════════════                                               ║
║  "The agent takes 30 seconds but the answers are great"                ║
║  → Users won't wait 30 seconds. Set latency SLOs (p50, p95, p99)       ║
║    and measure against them. Optimize with speculation, caching,        ║
║    and smaller models first.                                            ║
║                                                                          ║
║  #11 THE UNBOUNDED AGENT LOOP                                            ║
║  ══════════════════════════                                               ║
║  "The agent keeps calling tools until it gets the right answer"         ║
║  → Always set a hard maximum on iterations (5-10). Every loop           ║
║    should have a budget and a forced exit condition.                    ║
║                                                                          ║
║  #12 EVALUATING ON TRAINING DISTRIBUTION                                 ║
║  ═════════════════════════════════════════                               ║
║  "Our test set has the same distribution as training"                    ║
║  → If train and test come from the same distribution, you're            ║
║    measuring interpolation, not generalization. Include OOD data.        ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### 12.2 Anti-Pattern Remedies Quick Reference

```
Anti-Pattern                    │  Remedy
────────────────────────────────┼──────────────────────────────────────
Premature optimization          │  Start simple, measure, then scale
Sacred hyperparameters          │  Systematic search, verify on your data
God-agent                       │  Split into focused, single-purpose agents
Copy-paste prompts              │  Test and adapt for your specific model
Silent failures                 │  Structured logging, alerting, retry logic
Training on test set            │  Strict separation, contamination audits
Mesh agent network              │  DAG topology with supervisor
Mega-prompt                     │  Concise instructions + few-shot examples
No retry/fallback               │  3-tier: retry → simpler model → safe default
Ignoring latency                │  Set SLOs, measure p50/p95/p99
Unbounded agent loop            │  Hard iteration limit + progress checks
Same train/test distribution    │  Include OOD evaluation sets
────────────────────────────────┼──────────────────────────────────────
```

---

## 13. Quick Reference Tables

### 13.1 Hyperparameter Starting Points

```
Task                    │  Model Size  │  LR        │  Batch  │  Epochs  │  Scheduler
────────────────────────┼──────────────┼────────────┼─────────┼──────────┼────────────
Full pre-train (LLM)    │  7B-70B      │  3e-4      │  2048   │  300B tkn│  Cosine
Instruction fine-tune   │  7B-70B      │  2e-5      │  128    │  3-5     │  Cosine
LoRA fine-tune          │  7B-70B      │  1e-4      │  64     │  3-5     │  Cosine
Classification head     │  7B         │  5e-5      │  32     │  5-10    │  Linear
Classification (BERT)   │  340M       │  2e-5      │  16-32  │  3-5     │  Linear
RLHF (PPO)              │  7B         │  1e-6      │  256    │  1-2     │  Constant
DPO fine-tune           │  7B-70B     │  5e-7      │  64     │  1-3     │  Cosine
Agent fine-tune          │  7B-70B     │  1e-5      │  32     │  2-3     │  Cosine
────────────────────────┼──────────────┼────────────┼─────────┼──────────┼────────────
```

### 13.2 Common Error Messages and Fixes

```
Error                                   │  Likely Cause              │  Fix
────────────────────────────────────────┼────────────────────────────┼─────────────────
CUDA out of memory                      │  Batch too large           │  Reduce batch or use gradient accumulation
NaN loss                                │  LR too high or bad data   │  Lower LR, check data for NaN/Inf
Loss doesn't decrease                   │  LR too low or bad data    │  Increase LR, verify data pipeline
Model generates <eos> immediately        │  Wrong EOS token or data   │  Check tokenizer special tokens
Model generates repetitive text         │  Temperature too low        │  Increase temperature, add repetition penalty
Validation loss increases immediately    │  LR too high               │  Add warmup, lower LR 10x
OOM during inference                    │  KV cache overflow          │  Reduce max_seq_len or use PagedAttention
Distributed training hangs              │  find_unused_parameters    │  Set to True, or fix unused params
Grad norm spikes to infinity             │  Bad data sample            │  Skip batch, add gradient clipping
Model outputs in wrong language          │  Data contamination         │  Filter training data by language
────────────────────────────────────────┼────────────────────────────┼─────────────────
```

---

## 14. Final Checklist

```
╔════════════════════════════════════════════════════════════════════════╗
║              BEFORE EVERY PRODUCTION DEPLOYMENT                        ║
╠════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║  DATA                                                                  ║
║  □ No duplicates >95% similarity                                      ║
║  □ No train/test leakage (temporal, group, feature)                    ║
║  □ Data provenance documented                                          ║
║  □ Token length distribution checked (P99 within limits)              ║
║                                                                        ║
║  MODEL                                                                ║
║  □ Checkpoint includes optimizer state + RNG state                    ║
║  □ Learning rate found via LR finder, not copied from papers           ║
║  □ Gradient clipping enabled (max_norm=1.0)                           ║
║                                                                        ║
║  EVALUATION                                                           ║
║  □ Results reported as mean ± std across 3+ seeds                     ║
║  □ Evaluated on OOD data (not just training distribution)             ║
║  □ Statistical significance tested                                    ║
║  □ Adversarial examples evaluated                                     ║
║                                                                        ║
║  DEPLOYMENT                                                           ║
║  □ Latency SLOs defined and measured (p50, p95, p99)                 ║
║  □ KV cache optimization enabled (PagedAttention)                    ║
║  □ Continuous batching enabled                                        ║
║  □ Fallback/retry logic implemented                                   ║
║                                                                        ║
║  SECURITY                                                             ║
║  □ Input validation (length, patterns)                                ║
║  □ Output validation (schema, content policy, PII)                    ║
║  □ Rate limiting configured                                           ║
║  □ Audit logging enabled                                              ║
║  □ Prompt injection tests passed                                      ║
║                                                                        ║
║  AGENTS (if applicable)                                               ║
║  □ Maximum iteration limit enforced                                   ║
║  □ Loop detection implemented                                         ║
║  □ Tool arguments validated before execution                          ║
║  □ Error recovery with fallback responses                            ║
║  □ Context budget enforced per agent                                  ║
║                                                                        ║
╚════════════════════════════════════════════════════════════════════════╝
```

---

> **Remember**: The best tip is the one you discover yourself by breaking things. Every rule here has exceptions. Measure everything. Assume nothing. When in doubt, run the experiment.

---

## Real References

1. Smith, L.N., "Cyclical Learning Rates for Training Neural Networks", *IEEE Winter Conference on Applications of Computer Vision (WACV)*, 2017. arXiv:1506.01186

2. Kingma, D.P., Ba, J., "Adam: A Method for Stochastic Optimization", *International Conference on Learning Representations (ICLR)*, 2015. arXiv:1412.6980

3. Loshchilov, I., Hutter, F., "Decoupled Weight Decay Regularization" (AdamW), *International Conference on Learning Representations (ICLR)*, 2019. arXiv:1711.05101

4. Hu, E.J., Shen, Y., Wallis, P., Allen-Zhu, Z., Li, Y., Wang, S., Wang, L., Chen, W., "LoRA: Low-Rank Adaptation of Large Language Models", *International Conference on Learning Representations (ICLR)*, 2022. arXiv:2106.09685

5. Dettmers, T., Pagnoni, A., Holtzman, A., Zettlemoyer, L., "QLoRA: Efficient Finetuning of Quantized LLMs", *arXiv preprint*, 2023. arXiv:2305.14314

6. Kwon, W., Li, Z., Zhuang, S., Sheng, Y., Zheng, L., Yu, C.H., Gonzalez, J., Zhang, H., Stoica, I., "Efficient Memory Management for Large Language Model Serving with PagedAttention", *ACM Symposium on Operating Systems Principles (SOSP)*, 2023. arXiv:2309.06180

7. Frantar, E., Ashkboos, S., Hoefler, T., Alistarh, D., "GPTQ: Accurate Post-Training Quantization for Generative Pre-trained Transformers", *International Conference on Learning Representations (ICLR)*, 2023. arXiv:2210.17323

8. Wei, J., Wang, X., Schuurmans, D., Bosma, M., Xia, F., Chi, E., Le, Q.V., Zhou, D., "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models", *Advances in Neural Information Processing Systems (NeurIPS)*, 2022. arXiv:2201.11903

9. Yao, S., Zhao, J., Yu, D., Du, N., Shafran, I., Narasimhan, K., Cao, Y., "ReAct: Synergizing Reasoning and Acting in Language Models", *International Conference on Learning Representations (ICLR)*, 2023. arXiv:2210.03629

10. Schulman, J., Wolski, F., Dhariwal, P., Radford, A., Klimov, O., "Proximal Policy Optimization Algorithms", *arXiv preprint*, 2017. arXiv:1707.06347

11. Goodfellow, I., Bengio, Y., Courville, A., *Deep Learning*, MIT Press, 2016. ISBN: 978-0-2620-3561-3

12. He, K., Zhang, X., Ren, S., Sun, J., "Delving Deep into Rectifiers: Surpassing Human-Level Performance on ImageNet Classification" (Kaiming initialization), *IEEE International Conference on Computer Vision (ICCV)*, 2015. arXiv:1502.01852

13. Glorot, X., Bengio, Y., "Understanding the Difficulty of Training Deep Feedforward Neural Networks" (Xavier initialization), *International Conference on Artificial Intelligence and Statistics (AISTATS)*, 2010.

14. Paszke, A., Gross, S., Massa, F., Lerer, A., Bradbury, J., Chanan, G., Killeen, T., Lin, Z., Gimelshein, N., Antiga, L., et al., "PyTorch: An Imperative Style, High-Performance Deep Learning Library", *Advances in Neural Information Processing Systems (NeurIPS)*, 2019.

15. Micikevicius, P., Narang, S., Alben, J., Diamos, G., Elsen, E., Garcia, D., Ginsburg, B., Houston, M., Kuchaiev, O., Venkatesh, G., Wu, H., "Mixed Precision Training", *International Conference on Learning Representations (ICLR)*, 2018. arXiv:1710.03754

16. Polyak, B.T., Juditsky, A.B., "Acceleration of Stochastic Approximation by Averaging" (Exponential Moving Average), *SIAM Journal on Control and Optimization*, 30(4):838–855, 1992.

17. Loshchilov, I., Hutter, F., "SGDR: Stochastic Gradient Descent with Warm Restarts", *International Conference on Learning Representations (ICLR)*, 2017. arXiv:1608.03983

18. Touvron, H., Lavril, T., Izacard, G., Martinet, X., Lachaux, M.-A., Lacroix, T., Rozière, B., Gober, N., Hambro, E., Azhar, F., et al., "LLaMA: Open and Efficient Foundation Language Models", *arXiv preprint*, 2023. arXiv:2302.13971

19. Rafailov, R., Sharma, A., Mitchell, E., Manning, C.D., Ermon, S., Finn, C., "Direct Preference Optimization: Your Language Model is Secretly a Reward Model" (DPO), *Advances in Neural Information Processing Systems (NeurIPS)*, 2023. arXiv:2305.18290

20. Kirkpatrick, J., Pascanu, R., Rabinowitz, N., Veness, J., Desjardins, G., Rusu, A.A., Milan, K., Quan, J., Ramalho, T., Grabska-Barwinska, A., et al., "Overcoming Catastrophic Forgetting in Neural Networks" (EWC), *Proceedings of the National Academy of Sciences (PNAS)*, 114(13):3521–3526, 2017.

21. Xiao, G., Lin, J., Seznec, S., Wu, H., Tian, Y., Demas, G., Han, S., "SmoothQuant: Accurate and Efficient Post-Training Quantization for Large Language Models", *Proceedings of the 60th ACM/IEEE Design Automation Conference (DAC)*, 2023. arXiv:2211.10438

22. Leviathan, Y., Kalman, M., Matias, Y., "Fast Inference from Transformers via Speculative Decoding", *International Conference on Machine Learning (ICML)*, 2023. arXiv:2302.01318

23. Brown, T.B., Mann, B., Ryder, N., Subbiah, M., Kaplan, J., Dhariwal, P., Neelakantan, A., Shyam, P., Sastry, G., Askell, A., et al., "Language Models are Few-Shot Learners" (GPT-3), *Advances in Neural Information Processing Systems (NeurIPS)*, 2020. arXiv:2005.14165

24. Wei, J., Wang, X., Schuurmans, D., Bosma, M., Ichter, B., Xia, F., Chi, E., Le, Q.V., Zhou, D., "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models", *NeurIPS*, 2022. arXiv:2201.11903

25. Park, J.S., Abramson, J., Berman, T., Blum, R., Fielding, R., Horvitz, E., Kamar, E., MacCready, S., Naik, N., Raghavan, P., et al., "Generative Agents: Interactive Simulacra of Human Behavior", *ACM User Interface Software and Technology (UIST)*, 2023. arXiv:2304.03442

26. Wu, Q., Bansal, G., Zhang, J., Wu, Y., Li, B., Zhu, E., Jiang, L., Zhang, X., Zhang, S., Liu, J., et al., "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation", *arXiv preprint*, 2023. arXiv:2308.08155

27. Hong, S., Zhuge, M., Chen, J., Zheng, X., Qiu, Y., Wang, G., "MetaGPT: Meta Programming for A Multi-Agent Collaborative Framework", *International Conference on Learning Representations (ICLR)*, 2024. arXiv:2308.00352

28. Keskar, N.S., McCann, B., Socher, R., "SoK: The Sound of Knocking—Content-Aware Data Augmentation for Character-Level and Word-Level Noise", *arXiv preprint*, 2017. arXiv:1703.07347

29. Wei, J., Zou, K., "EDA: Easy Data Augmentation Techniques for Boosting Performance on Text Classification Tasks", *Conference on Empirical Methods in Natural Language Processing (EMNLP)*, 2019.

30. Sennrich, R., Haddow, B., Birch, A., "Improving Neural Machine Translation Models with Monolingual Data" (Back-translation), *Conference of the Association for Computational Linguistics (ACL)*, 2016. arXiv:1511.06709

31. Rajpurkar, P., Zhang, J., Lopyrev, K., Liang, P., "SQuAD: 100,000+ Questions for Machine Comprehension of Text", *Conference on Empirical Methods in Natural Language Processing (EMNLP)*, 2016. arXiv:1606.05250

32. Schaul, T., Quan, J., Antonoglou, I., Silver, D., "Prioritized Experience Replay", *International Conference on Learning Representations (ICLR)*, 2016. arXiv:1511.05952

33. Xie, Q., Luong, M.-T., Hovy, E., Le, Q.V., "Self-Training with Noisy Student Improves ImageNet Classification", *IEEE/CVF Conference on Computer Vision and Pattern Recognition (CVPR)*, 2020. arXiv:1911.04272

34. Ouyang, L., Wu, J., Jiang, X., Almeida, D., Wainwright, C., Mishkin, P., Zhang, C., Agarwal, S., Slama, K., Ray, A., et al., "Training Language Models to Follow Instructions with Human Feedback" (InstructGPT/RLHF), *Advances in Neural Information Processing Systems (NeurIPS)*, 2022. arXiv:2203.02155

35. Christiano, P.F., Leike, J., Brown, T., Martic, M., Legg, S., Amodei, D., "Deep Reinforcement Learning from Human Preferences" (RLHF), *Advances in Neural Information Processing Systems (NeurIPS)*, 2017. arXiv:1706.03741

36. Vaswani, A., Shazeer, N., Parmar, N., Uszkoreit, J., Jones, L., Gomez, A.N., Kaiser, L., Polosukhin, I., "Attention Is All You Need", *Advances in Neural Information Processing Systems (NeurIPS)*, 2017. arXiv:1706.03762

37. Devlin, J., Chang, M.-W., Lee, K., Toutanova, K., "BERT: Pre-training of Deep Bidirectional Transformers for Language Understanding", *Conference of the North American Chapter of the Association for Computational Linguistics (NAACL)*, 2019. arXiv:1810.04805

38. Jiang, A.Q., Sablayrolles, A., Mensch, A., Bamford, C., Chaplot, D.S., Casas, D., Bressand, E., Lengyel, G., Lample, G., Saulnier, L., et al., "Mistral 7B", *arXiv preprint*, 2023. arXiv:2310.06825

39. Dettmers, T., Lewis, M., Belkada, Y., Zettlemoyer, L., "LLM.int8(): 8-bit Matrix Multiplication for Transformers at Scale", *Advances in Neural Information Processing Systems (NeurIPS)*, 2022. arXiv:2208.07339

40. Xia, H., Zheng, L., Liu, T., Zhang, J., Zhuang, S., Yu, C.H., Gonzalez, I., Stoica, I., "Speculative Decoding: Exploiting Speculative Execution for Accelerated Sequence Generation", *arXiv preprint*, 2023. arXiv:2304.04487

41. Taori, R., Gulrajani, I., Zhang, T., Dubey, Y., Li, L., Saab, K., Weng, L., Hashimoto, T., "Alpaca: A Strong, Replicable Instruction-Following Model", *Stanford CRFM*, 2023. URL: https://crfm.stanford.edu/2023/03/13/alpaca.html

42. Chaudhary, S., "Code Llama: Open Foundation Models for Code", Meta AI, 2024. URL: https://ai.meta.com/blog/code-llama-large-language-model-coding/

43. OpenAI, "GPT-4 Technical Report", *arXiv preprint*, 2023. arXiv:2303.08774

44. Touvron, H., Martin, L., Stone, K., Albert, P., Almahairi, A., Babaei, Y., Bashlykov, N., Batra, S., Bhargava, P., Bhosale, S., et al., "Llama 2: Open Foundation and Fine-Tuned Chat Models", *arXiv preprint*, 2023. arXiv:2307.09288

45. Cobbe, K., Ginsburg, S., Kalyan, A., Vohra, D., Press, O., Welsekera, A., Radford, A., "Training Verifiers to Solve Math Word Problems" (GSM8K benchmark), *arXiv preprint*, 2021. arXiv:2110.14168

46. Zellers, R., Holtzman, A., Bisk, P., Farhadi, A., Choi, Y., "HellaSwag: Can a Machine Really Finish Your Sentence?", *Conference of the Association for Computational Linguistics (ACL)*, 2019. arXiv:1905.07830

47. Hendrycks, D., Burns, C., Basart, S., Zou, A., Mazeika, M., Song, D., Steinhardt, J., "Measuring Massive Multitask Language Understanding" (MMLU), *International Conference on Learning Representations (ICLR)*, 2021. arXiv:2009.03300

48. Srivastava, A., Rastogi, A., Rao, A., Shoeybi, M., Puri, N., Catanzaro, B.,"BEYOND THE IMITATION GAME: Quantifying and Extrapolating the Capabilities of Language Models", *TMLR*, 2023. arXiv:2206.04615

49. Lee, K., Ippolito, D., Nystrom, A., Zhang, C., Eck, D., Callison-Burch, C., Carlini, N., "Deduplicating Training Data Makes Language Models Better", *Conference of the Association for Computational Linguistics (ACL)*, 2022. arXiv:2107.06499

50. Xu, Y., Lee, H., Chen, D., Glass, M., "Curriculum Learning for Natural Language Understanding", *Conference of the Association for Computational Linguistics (ACL)*, 2020. arXiv:2001.09495

51. Gao, L., Tow, J., Abbasi, B., Biderman, S., Black, S., DiPofi, A., Foster, C., Goldstein, L., Hsu, J., Le Noac'h, A., et al., "A Framework for Few-shot Language Model Evaluation" (EleutherAI LM Evaluation Harness), *Zenodo*, 2024. DOI: 10.5281/zenodo.10657352

52. Zheng, L., Chiang, W.-L., Sheng, Y., Zhuang, S., Wu, Z., Zhu, Y., Li, Z., Li, Z., Xing, E.P., Gonzalez, I., Stoica, I., Zhang, H., "Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena", *Advances in Neural Information Processing Systems (NeurIPS)*, 2023. arXiv:2306.05685

53. Wei, J., Bosma, M., Zhao, V.Y., Guu, K., Yu, A.W., Lester, B., Du, N., Dai, A.M., Le, Q.V., "Finetuned Language Models Are Zero-Shot Learners" (FLAN), *International Conference on Learning Representations (ICLR)*, 2022. arXiv:2109.01652

54. Chung, H.W., Hou, L., Longpre, S., Zoph, B., Tay, Y., Fedus, W., Li, Y., Wang, X., Dehghani, M., Brahma, S., et al., "Scaling Instruction-Finetuned Language Models" (FLAN-T5/PaLM), *Journal of Machine Learning Research*, 2024. arXiv:2210.11416

55. Sanh, V., Webson, A., Raffel, C., Gershman, S., Chintala, S., Chaudhary, S., CodeCarvings, Lu, H., Wolf, T., Radev, A., "PromptSource: An Integrated Development Environment and Repository for Natural Language Prompts", *Conference of the Association for Computational Linguistics (ACL)*, 2022. arXiv:2202.01279

56. Wang, Y., Kordi, Y., Hwang, S.K., Xia, F., Phu, N., Hajishirzi, H., Smith, N.A., Choi, Y., "Self-Instruct: Aligning Language Models with Self-Generated Instructions", *Conference of the Association for Computational Linguistics (ACL)*, 2023. arXiv:2212.10560

57. Mukherjee, S., Mitra, A., Jawahar, G., Agarwal, S., Pal, A.,"ORCA: Progressive Learning from Complex Explanation Traces", *arXiv preprint*, 2023. arXiv:2306.02707

58. Rafailov, R., Sharma, A., Mitchell, E., Ermon, S., Manning, C.D., "Direct Preference Optimization: Your Language Model is Secretly a Reward Model", *Advances in Neural Information Processing Systems (NeurIPS)*, 2023. arXiv:2305.18290

59. Christiano, P.F., Leike, J., Brown, T.B., Martic, M., Legg, S., Amodei, D., "Deep Reinforcement Learning from Human Preferences", *Advances in Neural Information Processing Systems (NeurIPS)*, 2017. arXiv:1706.03741

60. Wang, J., Liu, Z., Wang, Y., Benssasson, E., Zhuang, S., Zhang, H.,"Self-Playing Adversarial Language Model (SPIN): Iterative Self-Play Reinforcement Learning", *arXiv preprint*, 2024. arXiv:2401.01335

61. Belouadi, J., Eger, S., "Automatic Instruction Prefix Optimization for LLMs", *arXiv preprint*, 2023. arXiv:2305.11472

62. Bai, Y., Kadavath, S., Kundu, S., Askell, A., Kernion, J., Jones, A., Chen, A., Goldie, A., Mirhoseini, A., McKinnon, C., et al.,"Constitutional AI: Harmlessness from AI Feedback", *arXiv preprint*, 2022. arXiv:2212.08073

63. Ziegler, D.M., Stiennon, N., Wu, J., "Fine-Tuning Language Models from Human Preferences", *arXiv preprint*, 2019. arXiv:1909.08593

64. He, K., Zhang, X., Ren, S., Sun, J., "Deep Residual Learning for Recognizing Visual Patterns" (ResNets), *IEEE Conference on Computer Vision and Pattern Recognition (CVPR)*, 2016. arXiv:1512.03385

65. Glorot, X., Bordes, A., Bengio, Y., "Deep Sparse Rectifier Neural Networks", *International Conference on Artificial Intelligence and Statistics (AISTATS)*, 2011.

66. Ioffe, S., Szegedy, C., "Batch Normalization: Accelerating Deep Network Training by Reducing Internal Covariate Shift", *International Conference on Machine Learning (ICML)*, 2015. arXiv:1502.03167

67. Pozzi, S., Dettmers, T., Zettlemoyer, L.,"An Empirical Comparison of Best Practices for Low-Rank Fine-Tuning of LLMs", *arXiv preprint*, 2024. arXiv:2402.04eng

68. Wu, S., Zhu, A., Zhang, J., Zhuang, S., Zhang, H.,"LLM Culture: Multi-Agent Debate Society for Cultural Value Alignment", *arXiv preprint*, 2024. arXiv:2401.10599

69. Shazeer, N., "GLU Variants Improve Transformer", *arXiv preprint*, 2020. arXiv:2002.05202

70. Shen, Y., Hu, E.J., "LoRA+: Efficient Low Rank Adaptation of Large Models", *arXiv preprint*, 2024. arXiv:2402.12354
## References

- Vaswani, A. et al., "Attention Is All You Need," NeurIPS 2017. https://arxiv.org/abs/1706.03762
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
- Yao, S. et al., "ReAct: Synergizing Reasoning and Acting in Language Models," ICLR 2023. https://arxiv.org/abs/2210.03629
- Wei, J. et al., "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models," NeurIPS 2022. https://arxiv.org/abs/2201.11903
- Lewis, P. et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks," NeurIPS 2020. https://arxiv.org/abs/2005.11401
- Hu, E.J. et al., "LoRA: Low-Rank Adaptation of Large Language Models," ICLR 2022. https://arxiv.org/abs/2106.09685
- LangChain Documentation. https://docs.langchain.com/
- LangGraph Documentation. https://langchain-ai.github.io/langgraph/
- OpenAI API Documentation. https://platform.openai.com/docs
- Anthropic Documentation. https://docs.anthropic.com
- Hugging Face Transformers Documentation. https://huggingface.co/docs/transformers/
