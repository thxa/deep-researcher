# Model Evaluation & Benchmarking: A Comprehensive Technical Guide

This guide provides an exhaustive treatment of model evaluation methodologies, benchmarking frameworks, and statistical testing procedures for modern AI systems — from classical ML to large language models.

---

## Table of Contents

1. [Evaluation Pipeline Architecture](#1-evaluation-pipeline-architecture)
2. [Classification Metrics](#2-classification-metrics)
3. [Regression Metrics](#3-regression-metrics)
4. [Ranking & Retrieval Metrics](#4-ranking--retrieval-metrics)
5. [NLP/LLM Evaluation Metrics](#5-nlpllm-evaluation-metrics)
6. [LLM-Specific Benchmarks](#6-llm-specific-benchmarks)
7. [Human Evaluation Methodologies](#7-human-evaluation-methodologies)
8. [LLM-as-Judge Evaluation](#8-llm-as-judge-evaluation)
9. [Safety & Bias Evaluation](#9-safety--bias-evaluation)
10. [Performance Benchmarking](#10-performance-benchmarking)
11. [Evaluation Frameworks](#11-evaluation-frameworks)
12. [Statistical Significance Testing](#12-statistical-significance-testing)

---

## 1. Evaluation Pipeline Architecture

A robust evaluation pipeline must be reproducible, versioned, and multi-faceted. Below is the canonical architecture:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     EVALUATION PIPELINE ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐ │
│  │  Model       │    │  Dataset     │    │  Evaluation Config       │ │
│  │  Checkpoint  │───▶│  Loader      │───▶│  (metrics, splits,       │ │
│  │  + Weights   │    │  + Sampler   │    │   judge prompts, etc.)  │ │
│  └──────────────┘    └──────┬───────┘    └────────────┬─────────────┘ │
│                             │                         │               │
│                             ▼                         ▼               │
│                    ┌────────────────────────────────────────┐        │
│                    │         INFERENCE ENGINE                │        │
│                    │  ┌─────────┐  ┌──────────┐             │        │
│                    │  │ Batch   │  │ Streaming │             │        │
│                    │  │ Runner  │  │ Runner    │             │        │
│                    │  └────┬────┘  └─────┬────┘             │        │
│                    └───────┼─────────────┼───────────────────┘        │
│                            │             │                            │
│                            ▼             ▼                            │
│              ┌─────────────────────────────────────┐                  │
│              │        METRIC COMPUTATION            │                  │
│              │  ┌──────────┐ ┌──────────┐          │                  │
│              │  │Automated │ │Human/     │          │                  │
│              │  │Metrics   │ │LLM-Judge │          │                  │
│              │  └────┬─────┘ └────┬─────┘          │                  │
│              └───────┼────────────┼────────────────┘                  │
│                      │            │                                    │
│                      ▼            ▼                                    │
│              ┌─────────────────────────────────────┐                  │
│              │        AGGREGATION & REPORTING       │                  │
│              │  ┌──────────┐ ┌──────────┐          │                  │
│              │  │Stat      │ │Dashboard │          │                  │
│              │  │Tests     │ │Visual.   │          │                  │
│              │  └────┬─────┘ └────┬─────┘          │                  │
│              └───────┼────────────┼────────────────┘                  │
│                      │            │                                    │
│                      ▼            ▼                                    │
│              ┌─────────────────────────────────────┐                  │
│              │  RESULTS STORE (versioned, cited)   │                  │
│              │  ┌────────┐ ┌────────┐ ┌────────┐  │                  │
│              │  │SQLite  │ │JSON    │ │MLflow  │  │                  │
│              │  │/DuckDB │ │Files   │ │Tracker │  │                  │
│              │  └────────┘ └────────┘ └────────┘  │                  │
│              └─────────────────────────────────────┘                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

Key principles:
- **Determinism**: Fix random seeds, pin library versions, freeze model weights.
- **Separation of concerns**: Inference, metric computation, and reporting must be decoupled.
- **Versioning**: Track dataset version, model checkpoint hash, and config SHA alongside results.

---

## 2. Classification Metrics

### 2.1 Confusion Matrix Anatomy

```
                        CONFUSION MATRIX ANATOMY
                        =========================

                    ┌──────────────────────────────────────┐
                    │          PREDICTED LABEL              │
                    │     ┌────────────┬────────────┐       │
                    │     │  Positive  │  Negative  │       │
        ┌───────────┼─────┼────────────┼────────────┤       │
        │           │     │            │            │       │
        │  ┌───────┐│  TP │  True      │  False     │       │
        │  │ Posi- ││     │  Positive  │  Negative  │       │
        │  │ tive  ││     │  ✓ correct  │  ✗ type II │       │
  ACTUAL│  └───────┘│     │            │            │       │
  LABEL │           ├─────┼────────────┼────────────┤       │
        │  ┌───────┐│  FN │  False      │  True      │       │
        │  │ Nega- ││     │  Positive   │  Negative  │       │
        │  │ tive  ││     │  ✗ type I   │  ✓ correct  │       │
        │  └───────┘│     │            │            │       │
        │           ├─────┼────────────┼────────────┤       │
                    │     └────────────┴────────────┘       │
                    └──────────────────────────────────────┘

  METRIC DERIVATIONS:
  ┌─────────────────────────────────────────────────────────────┐
  │  Accuracy    = (TP + TN) / (TP + TN + FP + FN)             │
  │  Precision   = TP / (TP + FP)          -- "of predicted  │
  │                                          positives..."     │
  │  Recall      = TP / (TP + FN)          -- "of actual      │
  │                                          positives..."     │
  │  Specificity = TN / (TN + FP)          -- "of actual       │
  │                                          negatives..."     │
  │  F1 Score    = 2 × (P × R) / (P + R)   -- harmonic mean   │
  │  Fβ Score    = (1 + β²) × (P × R) / (β² × P + R)         │
  └─────────────────────────────────────────────────────────────┘
```

### 2.2 ROC-AUC vs PR-AUC

```
    ROC CURVE                                    PR CURVE
    (varying threshold on decision fn)           (varying threshold — focus on + class)

  1.0 ┤ ●╶─────────────────────────╲          1.0 ┤ ●╲────────────────────────────
      │   ╲                          ╲            │    ╲
      │    ╲                          ╲           │     ╲
      │     ╲    ╲                     ╲          │      ╲    ╲
      │      ╲     ╲                    ╲         │       ╲     ╲   ← model
  TPR │       ╲      ╲    ← model       ╲  Prec. │        ╲      ╲
      │        ╲       ╲                  ╲       │         ╲       ╲
      │         ╲        ╲                  ╲      │          ╲        ╲
      │          ╲         ╲     ─ ─ ─ ─ ─  ╲     │           ╲         ╲
      │           ╲                     ─ ─ ─╲    │            ╲          ╲
      │            ╲                  ─ ─ ─ ─ ─╲   │             ╲           ╲
  0.0 ┤             ╲─────────────────────────╲ ● 0.0 ┤              ╲────────── ●
      └──────┬──────┬──────┬──────┬──────┬───          └──────┬──────┬──────┬──────┬──
           0.0    0.2    0.4    0.6    0.8   1.0             0.0    0.2    0.4    0.6   0.8
                   FPR (1 - Specificity)                     Recall (= TPR)

  AUC = area under curve                AUC = area under PR curve
  • Random baseline = diagonal (0.5)     • Random baseline = Prevalence (% positive)
  • Good for balanced classes            • Better for imbalanced datasets
  • Insensitive to class skew            • Sensitive to precision at high recall
```

**When to use which:**
| Scenario | Preferred Metric | Reason |
|---|---|---|
| Balanced classes | ROC-AUC | Symmetric view of both classes |
| Imbalanced classes | PR-AUC | Focuses on minority (positive) class |
| Costly false positives | Precision-focused PR | Emphasizes correctness of positive predictions |
| Costly false negatives | Recall-focused PR | Emphasizes catching all positives |

### 2.3 Multi-class Extensions

For K classes, extend via:

- **Macro-averaging**: Compute metric per class, then average unweighted.
  - `Macro-F1 = (1/K) Σ F1_k`
- **Micro-averaging**: Aggregate TP/FP/FN across all classes, then compute.
  - `Micro-F1 = Micro-Precision = Micro-Recall = Accuracy` (for single-label)
- **Weighted-averaging**: Weight each class's metric by its support (instance count).

---

## 3. Regression Metrics

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                    REGRESSION METRICS REFERENCE                  │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  Metric          Formula                         Properties      │
  │  ─────────       ────────                         ──────────      │
  │                                                                 │
  │  MSE             (1/n) Σ (yᵢ - ŷᵢ)²             Punishes        │
  │                                                   large errors   │
  │                                                                 │
  │  RMSE            √[(1/n) Σ (yᵢ - ŷᵢ)²]          Same unit as y │
  │                                                                 │
  │  MAE             (1/n) Σ |yᵢ - ŷᵢ|               Robust to      │
  │                                                   outliers       │
  │                                                                 │
  │  R²              1 - SS_res / SS_tot              Proportion of  │
  │                  = 1 - Σ(yᵢ-ŷᵢ)² / Σ(yᵢ-ȳ)²     var explained  │
  │                                                                 │
  │  Adjusted R²     1 - [(1-R²)(n-1) / (n-p-1)]     Penalizes      │
  │                                                   extra features │
  │                                                                 │
  │  ─── Key Relationships ─────────────────────────────────────      │
  │  • RMSE ≥ MAE (always); equality ⟺ all errors equal             │
  │  • R² can be negative (model worse than mean baseline)           │
  │  • Adjusted R² < R² when p > 0 and n is finite                  │
  │  • Adjusted R² decreases if added features don't improve fit     │
  │                                                                 │
  │  ─── When To Use ──────────────────────────────────────────      │
  │  • MSE/RMSE: When large errors are costly (finance, safety)      │
  │  • MAE:       When outliers should not dominate (robustness)     │
  │  • R²:        For explanatory power (comparing models)           │
  │  • Adj. R²:   For feature selection (prevents overfitting)       │
  └─────────────────────────────────────────────────────────────────┘
```

Additional considerations:
- **Huber Loss**: Smooth blend of MSE (for small errors) and MAE (for large errors); controlled by δ.
- **Log-Cosh Loss**: `log(cosh(y - ŷ))` — approximately MSE for small errors, MAE for large; twice differentiable.
- **Quantile Loss**: For prediction intervals; minimizes asymmetric penalties.

---

## 4. Ranking & Retrieval Metrics

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                RANKING & RETRIEVAL METRICS                       │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  MRR (Mean Reciprocal Rank):                                    │
  │  ┌─────────────────────────────────────────────────────┐       │
  │  │  MRR = (1/|Q|) Σ 1/rank_i                            │       │
  │  │  Where rank_i = rank of first relevant doc for q_i    │       │
  │  │  Measures: "how quickly does the first hit appear?"    │       │
  │  └─────────────────────────────────────────────────────┘       │
  │                                                                 │
  │  MAP (Mean Average Precision):                                   │
  │  ┌─────────────────────────────────────────────────────┐       │
  │  │  AP  = (1/m) Σₖ P(k) × rel(k)                       │       │
  │  │  MAP = (1/|Q|) Σ AP_q                                │       │
  │  │  Measures: "across all ranks, how are relevant        │       │
  │  │            documents distributed?"                     │       │
  │  └─────────────────────────────────────────────────────┘       │
  │                                                                 │
  │  NDCG (Normalized Discounted Cumulative Gain):                  │
  │  ┌─────────────────────────────────────────────────────┐       │
  │  │  DCG@k  = Σᵢ₌₁ᵏ (2^rel_i - 1) / log₂(i + 1)       │       │
  │  │  IDCG@k = DCG of ideal ranking                      │       │
  │  │  NDCG@k = DCG@k / IDCG@k                             │       │
  │  │  Measures: "are highly relevant docs ranked high?"     │       │
  │  │  Supports: graded relevance (not just binary)         │       │
  │  └─────────────────────────────────────────────────────┘       │
  │                                                                 │
  │  Hit Rate@k (Recall@k):                                         │
  │  ┌─────────────────────────────────────────────────────┐       │
  │  │  Hit@k = 1 if any relevant doc in top-k, else 0      │       │
  │  │  Measures: "does at least one relevant item appear    │       │
  │  │            in the first k results?"                    │       │
  │  └─────────────────────────────────────────────────────┘       │
  │                                                                 │
  │  CHOOSING A METRIC:                                              │
  │  ┌───────────────────────────────────────────────────────────┐  │
  │  │  Binary relevance?      → MAP or MRR                     │  │
  │  │  Graded relevance?      → NDCG                          │  │
  │  │  Only first hit matters? → MRR                           │  │
  │  │  Full retrieval quality? → MAP                          │  │
  │  │  Top-k matters?         → Hit Rate@k, NDCG@k            │  │
  │  └───────────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────┘
```

---

## 5. NLP/LLM Evaluation Metrics

### 5.1 Metric Taxonomy and Trade-offs

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                  NLP / LLM EVALUATION METRICS                        │
  ├─────────────────────────────────────────────────────────────────────┤
  │                                                                     │
  │   GENERATION ───┬─── Exact Match ────── BLEU (n-gram precision)    │
  │   METRICS       │                     ROUGE (n-gram recall)        │
  │                 │                     METEOR (aligned + stemming)   │
  │                 │                     chrF (char n-gram F-score)   │
  │                 │                                                    │
  │                 ├─── Embedding ─────── BERTScore (BERT embeddings) │
  │                 │                     MOVERScore (earth mover)      │
  │                 │                                                    │
  │                 └─── Perplexity ────── PPL = exp(Σ -log p(xᵢ)/N)  │
  │                                      Measures model uncertainty     │
  │                                                                     │
  │   ─── DETAILED COMPARISON ──────────────────────────────────────    │
  │                                                                     │
  │   Metric    Granularity  Strengths             Weaknesses            │
  │   ───────   ───────────  ─────────              ──────────           │
  │   BLEU      Word n-gram  Fast, corpus-level     Ignores recall,     │
  │                          correlates w/ human     synonyms,     order  │
  │                          judgment (MT)           matters too much    │
  │                                                                     │
  │   ROUGE     Word n-gram  Recall-focused,        Overlaps w/ BLEU;   │
  │                          good for summaries     still surface-level │
  │                                                                     │
  │   METEOR    Word align.  Recall+Precision,      Slower;               │
  │              +stemming    synonym-aware           requires resources  │
  │                                                (WordNet etc.)        │
  │                                                                     │
  │   chrF      Char n-gram  Handles morphology,     Less interpretable  │
  │                          good for morphological                      │
  │                          languages                                    │
  │                                                                     │
  │   BERTScore  Contextual  Captures semantics,    Computationally      │
  │              embeddings  robust to paraphrase    expensive; BERT     │
  │                          variation              bias possible         │
  │                                                                     │
  │   Perplexity Token-level Model-centric,        Not task-specific;   │
  │              probability model quality only      lower ≠ better task│
  │                                                 performance            │
  │                                                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Perplexity Deep Dive

Perplexity measures how well a language model predicts a sequence:

```
  PPL(W) = exp( - (1/N) Σᵢ log₂ P(wᵢ | w₁..wᵢ₋₁) )
```

- **Interpretation**: Effective branching factor at each token. PPL=10 means the model is, on average, as confused as if choosing uniformly from 10 tokens.
- **Range**: 1 (perfect) → ∞ (worst). GPT-2 (1542M) achieves ~35.76 on PTB; GPT-3 (175B) ~20.50 (zero-shot).
- **Pitfalls**: Not comparable across different tokenizers; domain-specific baseline varies; smoothing matters for rare words.

### 5.3 BLEU Score Computation

```
  BLEU = BP × exp( Σₙ₌₁ᴺ wₙ log pₙ )

  Where:
    pₙ = modified n-gram precision at order n
    wₙ = uniform weights (typically 1/N)
    BP = brevity penalty = min(1, exp(1 - r/c))
         r = reference length, c = candidate length

  Typical BLEU scores:
  ┌────────────────────────────────┐
  │  > 40   —  High quality MT    │
  │  25-40  —  Understandable     │
  │  10-25  —  Rough translation  │
  │  < 10   —  Nearly unusable    │
  └────────────────────────────────┘
```

---

## 6. LLM-Specific Benchmarks

### 6.1 Benchmark Taxonomy

```
                    LLM BENCHMARK TAXONOMY
                    ════════════════════════

         ┌─────────────────────────────────────────────────┐
         │            LLM EVALUATION                        │
         └────────────────────┬────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
     ┌────▼─────┐      ┌─────▼──────┐      ┌─────▼──────┐
     │ KNOWLEDGE │      │ REASONING  │      │  SAFETY &  │
     │ & FACTUAL │      │ & CODING   │      │ ALIGNMENT  │
     └────┬─────┘      └─────┬──────┘      └─────┬──────┘
          │                   │                   │
    ┌─────┼─────┐       ┌─────┼─────┐       ┌─────┼─────┐
    │     │     │       │     │     │       │     │     │
  MMLU  ARC  Hella-  GSM8K Human  MT-  Truth-  Toxi-  Real- 
              Swag          Eval Bench fulQA  GenHQ  Toxicity

  ┌─────────────────────────────────────────────────────────────────┐
  │  BENCHMARK DETAILS                                              │
  ├──────────┬──────────┬────────────┬────────────┬─────────────────┤
  │Benchmark │ Domain   │ Size       │ Metric     │ Focus           │
  ├──────────┼──────────┼────────────┼────────────┼─────────────────┤
  │ MMLU     │ 57 tasks │ ~16K Qs   │ Accuracy   │ World knowledge │
  │          │          │            │            │ & reasoning     │
  │ HumanEval│ Python   │ 164 probs  │ pass@k     │ Code generation │
  │ GSM8K    │ Math     │ 8.5K Qs    │ Accuracy   │ Multi-step math │
  │ HellaSwag│ Common-  │ ~10K exs   │ Accuracy   │ Commonsense     │
  │          │ sense    │            │            │ reasoning      │
  │ ARC      │ Science  │ 7.8K Qs    │ Accuracy   │ Scientific      │
  │          │          │            │            │ reasoning      │
  │TruthfulQA│ Miscon-  │ 817 Qs     │ MC2 /      │ Factual         │
  │          │ ceptions  │            │ generation │ truthfulness    │
  │ MT-Bench │ Multi-   │ 80 Qs ×   │ LLM-Judge  │ Multi-turn      │
  │          │ turn     │ 2 turns    │ (GPT-4)    │ conversation    │
  └──────────┴──────────┴────────────┴────────────┴─────────────────┘
```

### 6.2 Benchmark Details

**MMLU (Massive Multitask Language Understanding):**
- Covers 57 subjects from STEM to humanities at varying difficulty (elementary → professional).
- 5-shot evaluation; measures breadth and depth of pre-training knowledge.
- SOTA: GPT-4 ~86.4%, Claude 3 Opus ~86.8%, Llama-3-70B ~82.0%.

**HumanEval:**
- 164 hand-written Python programming problems with unit tests.
- Key metric: `pass@k` — probability that at least one of k samples passes all tests.
- `pass@k = 1 - C(n-c, k) / C(n, k)` where n = total samples, c = correct samples.
- SOTA: GPT-4 pass@1 ~67%, with specialized models reaching >90%.

**GSM8K (Grade School Math 8K):**
- 8.5K grade-school math word problems requiring 2-8 reasoning steps.
- Tests chain-of-thought reasoning capability.
- SOTA: GPT-4 ~92%, Llama-3-70B ~85% with CoT prompting.

**HellaSwag:**
- Sentence completion task testing commonsense reasoning.
- Originally adversarially constructed; requires understanding physical and social situations.

**ARC (AI2 Reasoning Challenge):**
- Science exam questions; ARC-Challenge (hard) vs ARC-Easy.
- ARC-Challenge: 2,590 questions requiring complex reasoning.

**TruthfulQA:**
- 817 questions designed to test whether models generate truthful answers vs common misconceptions.
- MC2 (multiple-choice) and generation metrics; a model that repeats myths scores poorly.

**MT-Bench:**
- 80 multi-turn questions across 8 categories; evaluated by GPT-4 as judge.
- Scores on 1-10 scale; captures conversational quality beyond single-turn accuracy.

---

## 7. Human Evaluation Methodologies

```
  ┌─────────────────────────────────────────────────────────────────┐
  │              HUMAN EVALUATION METHODOLOGIES                      │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐ │
  │  │  COMPARATIVE      │  │  ABSOLUTE        │  │ ERROR         │ │
  │  │  (Side-by-side)   │  │  (Single-sample) │  │ ENUMERATION   │ │
  │  │                  │  │                  │  │              │ │
  │  │  "Which is       │  │  Rate 1-5:       │  │ Count errors: │ │
  │  │   better: A      │  │  Fluency        │  │ • Factual     │ │
  │  │   or B?"          │  │  Coherence      │  │ • Logical     │ │
  │  │                  │  │  Helpfulness     │  │ • Safety      │ │
  │  │  Pros:           │  │  Relevance      │  │ • Typos/Gram. │ │
  │  │  • Low bias      │  │                  │  │              │ │
  │  │  • Fast           │  │  Pros:           │  │  Used for:    │ │
  │  │                  │  │  • Scalable      │  │  Error        │ │
  │  │  Cons:           │  │  • Independent   │  │  analysis     │ │
  │  │  • No absolute   │  │                  │  │  (not scoring) │ │
  │  │    scale         │  │  Cons:           │  │              │ │
  │  │  • Position      │  │  • Subjective    │  │              │ │
  │  │    bias          │  │  • No relative   │  │              │ │
  │  └──────────────────┘  │    information    │  └──────────────┘ │
  │                        └──────────────────┘                    │
  │                                                                 │
  │  ┌─────────────────────────────────────────────────────────┐   │
  │  │  INTER-RATER AGREEMENT METRICS                           │   │
  │  │  ─────────────────────────────────                       │   │
  │  │  • Cohen's κ:   Two raters, categorical              │   │
  │  │  • Fleiss' κ:   Multiple raters, categorical         │   │
  │  │  • Krippendorff's α: Any # of raters, any scale      │   │
  │  │  • ICC:         Continuous ratings, multiple raters  │   │
  │  │  • Spearman ρ:  Ordinal agreement (rank correlation)  │   │
  │  │                                                       │   │
  │  │  THUMBNAIL RULE: κ > 0.8 = strong agreement            │   │
  │  │                  κ 0.6-0.8 = moderate                  │   │
  │  │                  κ < 0.6 = needs revision              │   │
  │  └─────────────────────────────────────────────────────────┘   │
  │                                                                 │
  │  CROWDSOURCING BEST PRACTICES:                                  │
  │  • Minimum 3 annotators per sample                              │
  │  • Gold-standard trap questions every 10-20 items               │
  │  •qualification tasks before access                              │
  │  • Reject workers with <70% trap accuracy                       │
  │  • Pay above minimum wage; explicitly reject "free" labor       │
  │  • Shuffle presentation order to counter position bias          │
  └─────────────────────────────────────────────────────────────────┘
```

---

## 8. LLM-as-Judge Evaluation

### 8.1 Architecture

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                LLM-AS-JUDGE EVALUATION PIPELINE                  │
  │                                                                  │
  │  ┌────────────┐     ┌──────────────┐     ┌───────────────┐      │
  │  │ Candidate  │     │ Judge Prompt │     │ Judge Model   │      │
  │  │ Response   │────▶│ Template     │────▶│ (GPT-4,       │      │
  │  └────────────┘     │ (rubric +    │     │  Claude, etc.) │      │
  │                     │  few-shot)   │     └───────┬───────┘      │
  │  ┌────────────┐     └──────────────┘             │              │
  │  │ Reference  │──────────────┘                   │              │
  │  │ (optional) │                                  ▼              │
  │  └────────────┘                          ┌───────────────┐     │
  │                                           │ Structured    │     │
  │                                           │ Output Parser │     │
  │                                           │ (JSON/regex)  │     │
  │                                           └───────┬───────┘     │
  │                                                   │             │
  │                                                   ▼             │
  │                                          ┌───────────────┐     │
  │                                          │ Agreement     │     │
  │                                          │ Analysis      │     │
  │                                          │ (judge-human  │     │
  │                                          │  correlation)  │     │
  │                                          └───────────────┘     │
  └──────────────────────────────────────────────────────────────────┘
```

### 8.2 Judge Prompt Patterns

**Pairwise (Arena-style):**
```
  Given the prompt: {prompt}
  
  Response A: {response_a}
  Response B: {response_b}
  
  Which response is better? Consider:
  1. Helpfulness and relevance
  2. Accuracy and factual correctness
  3. Coherence and readability
  4. Safety and appropriateness
  
  Output JSON: {"winner": "A"|"B"|"tie", "reasoning": "..."}
```

**Single-point (Rubric-based):**
```
  Rate the following response on a 1-10 scale:
  
  Prompt: {prompt}
  Response: {response}
  
  Rubric:
  10: Excellent — comprehensive, accurate, well-structured
  7-9: Good — mostly correct, minor gaps
  4-6: Adequate — partially correct, notable issues
  1-3: Poor — incorrect, unhelpful, or unsafe
  
  Output JSON: {"score": <int>, "reasoning": "..."}
```

### 8.3 Known Biases and Mitigations

| Bias | Description | Mitigation |
|---|---|---|
| **Verbosity bias** | Longer responses preferred | Normalize by length; equalize formatting |
| **Position bias** | First response preferred | Randomize A/B order; run both orders |
| **Self-preference** | Judge prefers its own outputs | Use different model as judge |
| **Masking bias** | Judge recognizes its own style | Anonymize model names |
| **Format bias** | Markdown/lists preferred | Control for formatting |

---

## 9. Safety & Bias Evaluation

### 9.1 Safety Evaluation Checklist

```
  ┌─────────────────────────────────────────────────────────────────┐
  │          SAFETY EVALUATION CHECKLIST                            │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  ┌─ TOXICITY ────────────────────────────────────────────────┐ │
  │  │ ☐ Hate speech detection (identity attacks, slurs)         │ │
  │  │ ☐ Profanity and obscenity scoring                         │ │
  │  │ ☐ Threats and incitement to violence                      │ │
  │  │ ☐ Tools: Perspective API, ToxiGen, HateBERT               │ │
  │  │ ☐ Metric: Toxic fraction at threshold τ                  │ │
  │  └──────────────────────────────────────────────────────────┘ │
  │                                                                 │
  │  ┌─ FAIRNESS ────────────────────────────────────────────────┐ │
  │  │ ☐ Demographic parity: P(ŷ=1|A=a) = P(ŷ=1|A=b)          │ │
  │  │ ☐ Equalized odds: TPR and FPR equal across groups       │ │
  │  │ ☐ Counterfactual fairness: swap sensitive attr → same   │ │
  │  │   prediction                                              │ │
  │  │ ☐ Intersectional audit (e.g., race × gender)            │ │
  │  │ ☐ Tools: Aequitas, Fairlearn, AI Fairness 360           │ │
  │  └──────────────────────────────────────────────────────────┘ │
  │                                                                 │
  │  ┌─ ALIGNMENT / REFUSAL ────────────────────────────────────┐ │
  │  │ ☐ Harmful request refusal rate (e.g., "how to make X")  │ │
  │  │ ☐ Over-refusal rate (safe queries incorrectly refused)    │ │
  │  │ ☐ Instruction following vs. safety tradeoff               │ │
  │  │ ☐ Jailbreak robustness testing                            │ │
  │  │ ☐ Tools: AdvBench, Red-Eval, HarmBench, JailbreakBench  │ │
  │  └──────────────────────────────────────────────────────────┘ │
  │                                                                 │
  │  ┌─ REPRESENTATION ─────────────────────────────────────────┐ │
  │  │ ☐ Stereotype association tests (WinoBias, StereoSet)    │ │
  │  │ ☐ Sentiment parity across demographic mentions           │ │
  │  │ ☐ Occupational bias (who gets associated with what job)   │ │
  │  │ ☐ Cultural sensitivity across regions                    │ │
  │  └──────────────────────────────────────────────────────────┘ │
  │                                                                 │
  │  ┌─ PRIVACY ────────────────────────────────────────────────┐ │
  │  │ ☐ PII leakage rate (email, SSN, phone extraction)       │ │
  │  │ ☐ Training data extraction resistance                   │ │
  │  │ ☐ Membership inference attack resistance                │ │
  │  │ ☐ Tools: PrivQA, canary evaluation                      │ │
  │  └──────────────────────────────────────────────────────────┘ │
  │                                                                 │
  │  ┌─ ROBUSTNESS ─────────────────────────────────────────────┐ │
  │  │ ☐ Adversarial input resilience (typos, paraphrases)     │ │
  │  │ ☐ Distribution shift tolerance                           │ │
  │  │ ☐ Prompt injection resistance                            │ │
  │  │ ☐ Tools: StressTest, AdvGLUE, PromptBench               │ │
  │  └──────────────────────────────────────────────────────────┘ │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘
```

### 9.2 Toxicity Scoring

```
  Toxicity Score Distribution:

  Fraction
  of outputs
     │
 0.4 ┤                    ██
     │                    ██
 0.3 ┤              ██    ██    ██
     │        ██    ██    ██    ██
 0.2 ┤  ██    ██    ██    ██    ██    ██
     │  ██    ██    ██    ██    ██    ██    ██
 0.1 ┤  ██    ██    ██    ██    ██    ██    ██    ██
     │  ██    ██    ██    ██    ██    ██    ██    ██    ██
 0.0 ┤──██────██────██────██────██────██────██────██────██──▶
     │  0.0   0.1   0.2   0.3   0.4   0.5   0.6   0.7   0.8
     │              Toxicity Score (from Perspective API)
     │
     │  ── Model A (before RLHF): heavy right tail
     │  ── Model B (after RLHF):  concentrated left, low toxicity
     │
     │  KEY METRICS:
     │  • Toxic fraction @ τ=0.5: P(toxicity > 0.5)
     │  • Expected maximum toxicity over k samples
     │  • Toxicity probability: P(any of k samples toxic)
```

### 9.3 Fairness Metrics Formalized

| Metric | Formula | Operator |
|---|---|---|
| Demographic Parity | `P(ŷ=1|A=0) = P(ŷ=1|A=1)` | Difference < ε |
| Equalized Odds | `TPR₀ = TPR₁` and `FPR₀ = FPR₁` | Difference < ε |
| Predictive Parity | `PPV₀ = PPV₁` | Difference < ε |
| Individual Fairness | `d(f(x), f(x')) ≤ L·d(x, x')` | Lipschitz condition |

---

## 10. Performance Benchmarking

### 10.1 Performance Profiling Dashboard Layout

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                    LLM PERFORMANCE PROFILING DASHBOARD                   │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  ┌─── THROUGHPUT ─────────────────┐  ┌─── LATENCY (ms) ────────────────┐│
  │  │  Model: llama-3-70B            │  │                                ││
  │  │  Batch=1  █████  28 tok/s      │  │  TTFT   ████████  320ms       ││
  │  │  Batch=8  ████████████  210/s  │  │  TBT    ███        12ms       ││
  │  │  Batch=32 ██████████████  580/s│  │  E2E    ████████████  1.8s    ││
  │  │  Batch=64 ██████████████  590/s│  │  P50    ████████    1.6s     ││
  │  │                                │  │  P99    ██████████████  4.2s  ││
  │  └────────────────────────────────┘  └────────────────────────────────┘│
  │                                                                         │
  │  ┌─── GPU MEMORY ─────────────────┐  ┌─── TOKEN ECONOMICS ────────────┐│
  │  │  ██ KV Cache  ████████ 48.2GB  │  │  Prompt tokens/req:  1,247    ││
  │  │  ██ Weights   ██████████ 130GB │  │  Completion tokens:    412    ││
  │  │  ██ Activ.    ████      8.1GB  │  │  Total throughput:  580tok/s  ││
  │  │  ██ Available  ████████ 31.7GB │  │  Cache hit rate:     72.3%    ││
  │  └────────────────────────────────┘  └────────────────────────────────┘│
  │                                                                         │
  │  ┌─── LATENCY DISTRIBUTION ───────────────────────────────────────────┐│
  │  │                                                                    ││
  │  │  Frequency                                                         ││
  │  │    ██                                                               ││
  │  │    ██ ██                                                            ││
  │  │    ██ ██ ██                                                         ││
  │  │ ██ ██ ██ ██ ██                                                      ││
  │  │ ██ ██ ██ ██ ██ ██                                                   ││
  │  │──██─██─██─██─██─██──────────────────────────────────▶ Latency(ms) ││
  │  │   200 400 600 800 1k  1.2 1.4 1.6 1.8 2k 2.2 2.4 2.6 2.8 3k 3.2  ││
  │  │                          ▲ P50            ▲ P95    ▲ P99           ││
  │  └────────────────────────────────────────────────────────────────────┘│
  │                                                                         │
  │  KEY DEFINITIONS:                                                       │
  │  ──────────────────                                                     │
  │  TTFT  = Time To First Token (prefill latency)                          │
  │  TBT   = Time Between Tokens (decode latency per token)                │
  │  E2E   = End-to-End (prompt in → last token out)                       │
  │  Throughput = tokens/second (aggregate across batch)                   │
  │  Memory = Peak GPU memory during inference                              │
  └─────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Performance Metrics Definitions

| Metric | Formula | What it measures |
|---|---|---|
| TTFT | Time from request to first output token | Prefill/encoding speed |
| TBT | Time between consecutive output tokens | Decode speed per token |
| Throughput | Total output tokens / wall-clock time | System capacity |
| Concurrency | Max simultaneous requests within SLA | Served requests |
| Memory peak | Max VRAM during inference run | Hardware requirements |
| KV cache utilization | Fraction of KV cache capacity used | Memory efficiency |

### 10.3 Benchmarking Best Practices

1. **Warm-up runs**: Discard the first 3-5 inferences to stabilize GPU clocks and caching.
2. **Fixed random seed**: Ensure reproducible generation across runs.
3. **Multiple batch sizes**: Profile at batch=1 (latency-optimal) through batch=max (throughput-optimal).
4. **Specify hardware**: GPU model, CUDA version, driver version, quantization level.
5. **Report percentiles**: P50, P95, and P99 latency — means can hide outliers.
6. **Isolate prefill vs decode**: TTFT and TBT have fundamentally different scaling characteristics.

---

## 11. Evaluation Frameworks

### 11.1 Framework Comparison

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                EVALUATION FRAMEWORKS OVERVIEW                    │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  ┌─────────────────────────────────────────────────────────┐   │
  │  │  HELM (Holistic Evaluation of Language Models)           │   │
  │  │  ────────────────────────────────────────────             │   │
  │  │  • 16 scenarios × 7 metrics = 112 evaluation cells      │   │
  │  │  • Scenarios: QA, summarization, reasoning, toxicity...   │   │
  │  │  • Metrics: accuracy, calibration, robustness, fairness, │   │
  │  │    efficiency, bias, toxicity                             │   │
  │  │  • 50+ models evaluated with full transparency           │   │
  │  │  • Trade-off analysis (e.g., accuracy vs. toxicity)       │   │
  │  └─────────────────────────────────────────────────────────┘   │
  │                                                                 │
  │  ┌─────────────────────────────────────────────────────────┐   │
  │  │  BIG-bench (Beyond the Imitation Game)                   │   │
  │  │  ──────────────────────────────────────────               │   │
  │  │  • 200+ tasks across 40+ capabilities                   │   │
  │  │  • Community-contributed (150+ authors)                  │   │
  │  │  • BIG-bench Hard: 23 hardest tasks where models         │   │
  │  │    significantly underperform human experts               │   │
  │  │  • Novel capabilities: theory of mind, social reasoning  │   │
  │  │  • Keyword-based task categorization                     │   │
  │  └─────────────────────────────────────────────────────────┘   │
  │                                                                 │
  │  ┌─────────────────────────────────────────────────────────┐   │
  │  │  Open LLM Leaderboard (HuggingFace)                      │   │
  │  │  ──────────────────────────────────────                   │   │
  │  │  • Automated evaluation on community submissions          │   │
  │  │  • Tasks: ARC, HellaSwag, MMLU, TruthfulQA, WinoGrande  │   │
  │  │  • Average score ranking (v1) and per-task ranking (v2)  │   │
  │  │  • Model size/efficiency tradeoffs visible               │   │
  │  │  • Contamination detection and versioning                 │   │
  │  └─────────────────────────────────────────────────────────┘   │
  │                                                                 │
  │  ┌─────────────────────────────────────────────────────────┐   │
  │  │  Other Notable Frameworks                                 │   │
  │  │  ──────────────────────                                   │   │
  │  │  • lm-eval-harness (Eleuther): Configurable, extensible  │   │
  │  │  • AlpacaEval: Fast auto-evaluator for instruction-follow │   │
  │  │  • FastChat MT-Bench: Arena-style LLM judge              │   │
  │  │  • lm-harness: Lightweight benchmark runner               │   │
  │  │  • Dynabench: Dynamic, adversarial dataset creation      │   │
  │  │  • EvalPlus: Rigorous HumanEval augmentation              │   │
  │  └─────────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────────┘
```

### 11.2 Setting Up `lm-eval-harness`

```python
# Installation and basic evaluation
pip install lm-eval

# Evaluate on MMLU and HellaSwag
lm_eval --model hf \
    --model_args "pretrained=meta-llama/Llama-3-8B" \
    --tasks mmlu,hellaswag \
    --batch_size auto

# Custom task configuration
lm_eval --model hf \
    --model_args "pretrained=meta-llama/Llama-3-8B" \
    --include_path ./custom_tasks/ \
    --tasks my_custom_task \
    --limit 500 \
    --output_path ./results/
```

---

## 12. Statistical Significance Testing

### 12.1 Evaluation Workflow Decision Tree

```
                        EVALUATION WORKFLOW DECISION TREE
                        ═══════════════════════════════════

                              ┌──────────┐
                              │ Evaluate │
                              │  Model   │
                              └────┬─────┘
                                   │
                          ┌────────▼────────┐
                          │ What type of    │
                          │ task?           │
                          └──┬─────┬────┬───┘
                             │     │    │
                    ┌────────┘     │    └────────┐
                    ▼              ▼             ▼
              ┌─────────┐   ┌──────────┐   ┌──────────┐
              │Classif. │   │ Ranking  │   │Generative│
              └────┬────┘   └────┬─────┘   └────┬─────┘
                   │             │              │
                   ▼             ▼              ▼
        ┌──────────────┐  ┌────────────┐  ┌──────────────┐
        │Imbalanced?   │  │Graded      │  │Reference-    │
        │              │  │relevance?  │  │based?        │
        └──┬──────┬────┘  └──┬─────┬───┘  └──┬──────┬────┘
           │      │          │     │         │      │
        No│   Yes│       No│  Yes│      No│  Yes│
           │      │          │     │         │      │
           ▼      ▼          ▼     ▼         ▼      ▼
        ┌─────┐ ┌──────┐ ┌────┐ ┌─────┐ ┌───────┐ ┌─────────┐
        │ROC- │ │PR-   │ │MAP │ │NDCG │ │Human/ │ │BLEU/    │
        │AUC  │ │AUC   │ │    │ │     │ │LLM   │ │ROUGE/   │
        │     │ │      │ │    │ │     │ │Judge  │ │BERTScore│
        └──┬──┘ └──┬───┘ └──┬─┘ └──┬──┘ └──┬────┘ └────┬────┘
           │       │        │      │       │           │
           └───┬───┘        └──┬───┘       │           │
               │               │           │           │
               ▼               ▼           ▼           ▼
        ┌──────────────────────────────────────────────────────┐
        │          STATISTICAL SIGNIFICANCE TESTING             │
        │                                                      │
        │  Is the sample size > 30?                            │
        │     ┌──────YES──────┐     ┌──────NO──────┐         │
        │     │               │     │               │         │
        │     ▼               │     ▼               │         │
        │  ┌─────────┐        │  ┌──────────────┐   │         │
        │  │Paired   │        │  │Permutation   │   │         │
        │  │t-test   │        │  │test or       │   │         │
        │  │or       │        │  │bootstrap CI  │   │         │
        │  │McNemar  │        │  │              │   │         │
        │  └─────────┘        │  └──────────────┘   │         │
        │                     │                     │         │
        │  Normality assumed? │   Otherwise         │         │
        │     │          │    │                     │         │
        │   YES│        NO│   │                     │         │
        │     │           │   │                     │         │
        │     ▼           ▼   │                     │         │
        │  Parametric  Wilcoxon                     │         │
        │  tests      signed-rank                   │         │
        │                    ┌──────────────────────┘         │
        │                    │                                │
        │                    ▼                                │
        │          ┌────────────────────┐                     │
        │          │ Report: mean ± CI,│                     │
        │          │ p-value, effect    │                     │
        │          │ size (Cohen's d)   │                     │
        │          └────────────────────┘                     │
        └──────────────────────────────────────────────────────────────┘
```

### 12.2 Statistical Tests Reference

```
  ┌──────────────────────────────────────────────────────────────────┐
  │           STATISTICAL SIGNIFICANCE TESTS FOR ML                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Test                  When to use            Example            │
  │  ──────────────        ───────────             ───────            │
  │                                                                  │
  │  Paired t-test         Two models,             Compare acc of     │
  │                        normal diffs            model A vs B       │
  │                                                                  │
  │  McNemar's test        Two models,             Compare error      │
  │                        paired binary           patterns on         │
  │                        outcomes                 same examples     │
  │                                                                  │
  │  Wilcoxon signed-rank  Two models,             Non-normal acc     │
  │                        paired, non-normal      diffs              │
  │                                                                  │
  │  Bootstrap CI          Any metric,             Estimate CI for    │
  │                        small sample            F1 score           │
  │                                                                  │
  │  Permutation test      Any metric,             Compare NDCG of    │
  │                        no distributional       two rankers        │
  │                        assumptions                                 │
  │                                                                  │
  │  Friedman test         >2 models on            Compare 4 models   │
  │                        multiple datasets       on 5 benchmarks    │
  │                                                                  │
  │  Nemenyi post-hoc      After Friedman,         Which pairs differ │
  │                        pairwise comparisons    significantly?      │
  │                                                                  │
  │  ─── EFFECT SIZE ────────────────────────────────────────────    │
  │                                                                  │
  │  Cohen's d = (μ₁ - μ₂) / σ_pooled                               │
  │                                                                  │
  │  │d│    Interpretation                                            │
  │  <0.2   Negligible                                                │
  │  0.2    Small                                                     │
  │  0.5    Medium                                                    │
  │  0.8    Large                                                     │
  │                                                                  │
  │  ─── BOOTSTRAP CONFIDENCE INTERVALS ─────────────────────────    │
  │                                                                  │
  │  For a metric M with dataset D of size n:                        │
  │                                                                  │
  │  1. For b = 1..B (B = 10,000):                                  │
  │     a. Sample n instances from D with replacement → D'_b          │
  │     b. Compute M_b = metric(D'_b)                              │
  │  2. Sort M_1, M_2, ..., M_B                                     │
  │  3. 95% CI = [M_(0.025×B), M_(0.975×B)]                        │
  │                                                                  │
  │  ─── MULTIPLE COMPARISONS CORRECTION ───────────────────────    │
  │                                                                  │
  │  When testing k hypotheses at significance level α:              │
  │                                                                  │
  │  • Bonferroni: α_adj = α / k                                     │
  │    — Simple, very conservative                                   │
  │  • Holm-Bonferroni: Sequentially reject, adjust stepwise         │
  │    — Less conservative, still valid                             │
  │  • Benjamini-Hochberg (FDR): Control false discovery rate        │
  │    — Best for many comparisons; less power loss                  │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
```

### 12.3 Practical Significance Testing Pipeline

```python
import numpy as np
from scipy import stats

def paired_bootstrap_test(scores_a, scores_b, n_boot=10000, ci=0.95):
    """Test whether model A significantly outperforms model B."""
    diff = np.array(scores_a) - np.array(scores_b)
    observed = np.mean(diff)
    
    bootstrap_means = []
    for _ in range(n_boot):
        sample = np.random.choice(diff, size=len(diff), replace=True)
        bootstrap_means.append(np.mean(sample))
    
    bootstrap_means = np.sort(bootstrap_means)
    alpha = 1 - ci
    lower = bootstrap_means[int(alpha/2 * n_boot)]
    upper = bootstrap_means[int((1 - alpha/2) * n_boot)]
    
    # Two-sided p-value
    p_value = 2 * min(
        np.mean(bootstrap_means <= 0),
        np.mean(bootstrap_means >= 0)
    )
    
    # Cohen's d
    pooled_std = np.std(diff, ddof=1)
    cohens_d = observed / pooled_std if pooled_std > 0 else float('inf')
    
    return {
        'mean_diff': observed,
        'ci_lower': lower,
        'ci_upper': upper,
        'p_value': p_value,
        'cohens_d': cohens_d,
        'significant': p_value < (1 - ci)
    }
```

---

## Quick Reference: Metric Selection Guide

| Problem Type | Primary Metric | Secondary | When to Avoid |
|---|---|---|---|
| Binary classification (balanced) | ROC-AUC | F1 | Imbalanced data |
| Binary classification (imbalanced) | PR-AUC | F1 | Don't use accuracy |
| Multi-class classification | Macro-F1 | Accuracy | Imbalanced: avoid accuracy |
| Multi-label classification | Micro-F1 | mAP | Don't use accuracy |
| Regression (normal errors) | RMSE | R² | Heavy outliers |
| Regression (robust) | MAE | Huber loss | When large errors matter |
| Information retrieval | NDCG@10 | MAP | When only 1st hit matters → MRR |
| Text generation (MT) | BLEU | chrF | When semantic overlap > n-gram |
| Summarization | ROUGE-L | BERTScore | When fluency > overlap |
| Code generation | pass@k | HumanEval | Don't use BLEU |
| LLM alignment | MT-Bench | Human eval | Don't rely on auto-metrics alone |
| LLM safety | Toxicity% | Refusal rate | Must include red-teaming |

---

*This guide provides the foundational framework for principled model evaluation. Always pair automated metrics with human evaluation, report confidence intervals, and test for statistical significance before drawing conclusions about model performance.*

---

## Real References

### Automated Evaluation Metrics

1. Papineni, K., Roukos, S., Ward, T., & Zhu, W.-J. (2002). "BLEU: A Method for Automatic Evaluation of Machine Translation." *Proceedings of the 40th Annual Meeting of the Association for Computational Linguistics (ACL 2002)*, pp. 311–318. DOI: [10.3115/1073083.1073135](https://doi.org/10.3115/1073083.1073135)

2. Lin, C.-Y. (2004). "ROUGE: A Package for Automatic Evaluation of Summaries." *Text Summarization Branches Out: Proceedings of the ACL 2004 Workshop*, pp. 74–81. DOI: [10.3115/1218955.1218960](https://doi.org/10.3115/1218955.1218960)

3. Banerjee, S. & Lavie, A. (2005). "METEOR: An Automatic Metric for MT Evaluation with Improved Correlation with Human Judgments." *Proceedings of the ACL Workshop on Intrinsic and Extrinsic Evaluation Measures for Machine Translation and/or Summarization*, pp. 65–72. DOI: [10.3115/1626521.1626532]

4. Popović, M. (2015). "chrF: Character n-gram F-score for Automatic MT Evaluation." *Proceedings of the Tenth Workshop on Statistical Machine Translation (WMT 2015)*, pp. 392–395. DOI: [10.18653/v1/W15-3049](https://doi.org/10.18653/v1/W15-3049)

5. Zhang, T., Kishore, V., Wu, F., Weinberger, K. Q., & Artzi, Y. (2020). "BERTScore: Evaluating Text Generation with BERT." *Proceedings of the 8th International Conference on Learning Representations (ICLR 2020)*. arXiv: [1904.09675](https://arxiv.org/abs/1904.09675)

6. Zhao, W., Peyrard, M., Liu, P., Gao, Y., Meyer, T., & Bansal, M. (2019). "MoverScore: Text Generation Evaluating with Contextualized Embeddings and Earth Mover Distance." *Proceedings of the 2019 Conference on Empirical Methods in Natural Language Processing (EMNLP 2019)*, pp. 563–578. DOI: [10.18653/v1/D19-1053](https://doi.org/10.18653/v1/D19-1053)

### LLM Benchmarks

7. Hendrycks, D., Burns, C., Basart, S., Zou, A., Mazeika, M., Song, D., & Steinhardt, J. (2021). "Measuring Massive Multitask Language Understanding." *Proceedings of the 9th International Conference on Learning Representations (ICLR 2021)*. arXiv: [2009.03300](https://arxiv.org/abs/2009.03300)

8. Chen, M., Tworek, J., Jun, H., Yuan, Q., Pinto, H. P. de O., Kaplan, J., Edwards, H., et al. (2021). "Evaluating Large Language Models Trained on Code." arXiv: [2107.03374](https://arxiv.org/abs/2107.03374)

9. Cobbe, K., Kosaraju, V., Bavarian, M., Chen, L., Jun, H., Kaiser, L., Plappert, M., Tworek, J., Hilton, J., Nakano, R., et al. (2021). "Training Verifiers to Solve Math Word Problems." arXiv: [2110.14168](https://arxiv.org/abs/2110.14168)

10. Zellers, R., Holtzman, A., Bisk, Y., Farhadi, A., & Choi, Y. (2019). "HellaSwag: Can a Machine Really Finish Your Sentence?" *Proceedings of the 57th Annual Meeting of the Association for Computational Linguistics (ACL 2019)*, pp. 4791–4800. DOI: [10.18653/v1/P19-1472](https://doi.org/10.18653/v1/P19-1472). arXiv: [1905.07830](https://arxiv.org/abs/1905.07830)

11. Clark, P., Cowhey, I., Etzioni, O., Khot, T., Sabharwal, A., Schoenick, M., & Tafjord, O. (2018). "Think You Have Solved Question Answering? Try ARC, the AI2 Reasoning Challenge." arXiv: [1803.05457](https://arxiv.org/abs/1803.05457)

12. Lin, S., Hilton, J., & Evans, O. (2022). "TruthfulQA: Measuring How Models Mimic Human Falsehoods." *Proceedings of the 60th Annual Meeting of the Association for Computational Linguistics (ACL 2022)*, pp. 3214–3252. DOI: [10.18653/v1/2022.acl-long.229](https://doi.org/10.18653/v1/2022.acl-long.229). arXiv: [2109.07958](https://arxiv.org/abs/2109.07958)

13. Zheng, L., Chiang, W.-L., Sheng, Y., Zhuang, S., Wu, Z., Zhuang, Y., Lin, Z., Li, Z., Li, D., Xing, E., et al. (2023). "Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena." *Advances in Neural Information Processing Systems 36 (NeurIPS 2023)*. arXiv: [2306.05685](https://arxiv.org/abs/2306.05685)

### Comprehensive Evaluation Frameworks

14. Liang, P., Bommasani, R., Lee, T., et al. (2023). "Holistic Evaluation of Language Models (HELM)." *Transactions on Machine Learning Research (TMLR) 2023*. arXiv: [2211.09110](https://arxiv.org/abs/2211.09110)

15. Srivastava, A., Rastogi, A., Rao, A., Shoeb, A. A. M., Abid, A., Fisch, A., Brown, A. R., et al. (2023). "Beyond the Imitation Game: Benchmarking and Measuring Progress in Constrained and Unconstrained Language Generation (BIG-bench)." *Proceedings of the 61st Annual Meeting of the Association for Computational Linguistics (ACL 2023)*, pp. 11002–11045. arXiv: [2206.04615](https://arxiv.org/abs/2206.04615)

### Human Evaluation & Inter-Rater Agreement

16. Artstein, R. & Poesio, M. (2008). "Inter-Coder Agreement for Computational Linguistics." *Computational Linguistics*, 34(4), pp. 555–596. DOI: [10.1162/coli.07-034-R2](https://doi.org/10.1162/coli.07-034-R2)

17. Cohen, J. (1960). "A Coefficient of Agreement for Nominal Scales." *Educational and Psychological Measurement*, 20(1), pp. 37–46. DOI: [10.1177/001316446002000104](https://doi.org/10.1177/001316446002000104)

18. Krippendorff, K. (2011). "Computing Krippendorff's Alpha-Reliability." *Philadelphia: Annenberg School for Communication, University of Pennsylvania*. URL: [https://www.asc.upenn.edu/](https://www.asc.upenn.edu/)

### Statistical Significance Testing for NLP/ML

19. Dror, R., Segev, S., Shlomov, N., & Reichart, R. (2019). "Deep Bias-Aware Statistical Testing for NLP." *Proceedings of the 2019 Conference on Empirical Methods in Natural Language Processing (EMNLP 2019)*. arXiv: [1909.03596](https://arxiv.org/abs/1909.03596)

20. Koehn, P. (2004). "Statistical Significance Tests for Machine Translation Evaluation." *Proceedings of the 2004 Conference on Empirical Methods in Natural Language Processing (EMNLP 2004)*, pp. 388–395.

21. Efron, B. & Tibshirani, R. J. (1994). *An Introduction to the Bootstrap*. Chapman and Hall/CRC. ISBN: 978-0412042317. DOI: [10.1201/9780429246593](https://doi.org/10.1201/9780429246593)

### Fairness, Bias, and Safety Evaluation

22. Hartvigsen, T.,Gabriel, S., Subramanian, H., Paladugu, A., & Mihalcea, R. (2022). "ToxiGen: A Large-Scale Machine-Generated Dataset for Adversarial and Neutral Toxicity Benchmarking." *Proceedings of the 2022 Conference on Empirical Methods in Natural Language Processing (EMNLP 2022)*. arXiv: [2203.09562](https://arxiv.org/abs/2203.09562)

23. Nangia, N., Vania, C., Bhalerao, R., & Bowman, S. R. (2020). "CrowS-Pairs: A Challenge Dataset for Measuring Social Biases in Masked Language Models." *Proceedings of the 2020 Conference on Empirical Methods in Natural Language Processing (EMNLP 2020)*. arXiv: [2010.00133](https://arxiv.org/abs/2010.00133)

24. Zou, A., Wang, Z., Kolter, J. Z., & Fredrikson, M. (2023). "Universal and Transferable Adversarial Attacks on Aligned Language Models." arXiv: [2307.15043](https://arxiv.org/abs/2307.15043)

25. Mazeika, M., Phan, L., Yin, X., Zou, A., Wang, Z., Hong, N., et al. (2024). "HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal." arXiv: [2402.04249](https://arxiv.org/abs/2402.04249)

26. Zhao, J., Wang, T., Yatskar, M., Orabona, V., & Chang, K.-W. (2018). "Gender Bias in Coreference Resolution: Evaluation and Debiasing Methods." *Proceedings of the 2018 Conference of the North American Chapter of the Association for Computational Linguistics: Human Language Technologies (NAACL-HLT 2018)*, pp. 15–20. DOI: [10.18653/v1/N18-2003](https://doi.org/10.18653/v1/N18-2003)

### RLHF Evaluation & Alignment

27. Ouyang, L., Wu, J., Jiang, X., Almeida, D., Wainwright, C., Mishkin, P., Zhang, C., et al. (2022). "Training Language Models to Follow Instructions with Human Feedback." *Advances in Neural Information Processing Systems 35 (NeurIPS 2022)*. arXiv: [2203.02155](https://arxiv.org/abs/2203.02155)

28. Bai, Y., Jones, A., Ndousse, K., Askell, A., Chen, A., DasSarma, N., Drain, D., et al. (2022). "Training a Helpful and Harmless Assistant with Reinforcement Learning from Human Feedback." arXiv: [2204.05862](https://arxiv.org/abs/2204.05862)

29. Gao, L., Schulman, J., Hilton, J., Schulman, J., & Hilton, J. (2023). "Scaling Laws for Reward Model Overoptimization." *Proceedings of the 40th International Conference on Machine Learning (ICML 2023)*. arXiv: [2210.10760](https://arxiv.org/abs/2210.10760)

### LLM-as-Judge and Arena Evaluation

30. Chiang, W.-L., Zheng, L., Sheng, Y., Dun, C., Liang, T.,antis, N., Li, Z., Zhuang, S., Wu, Z., et al. (2024). "Chatbot Arena: An Open Platform for Evaluating LLMs by Human Preference." *Proceedings of the 41st International Conference on Machine Learning (ICML 2024)*. arXiv: [2403.04132](https://arxiv.org/abs/2403.04132)

31. Dubois, Y., Li, C. J., Taori, R., Zhang, T., Gupta, S., Li, Y., et al. (2024). "AlpacaFarm: A Simulation Framework for Methods that Learn from Human Feedback." *Advances in Neural Information Processing Systems 36 (NeurIPS 2023)*. arXiv: [2305.14387](https://arxiv.org/abs/2305.14387)

### Code Evaluation

32. Austin, J., August, T., Chris, D., et al. (2021). "Program Synthesis with Large Language Models." arXiv: [2108.07732](https://arxiv.org/abs/2108.07732)

33. Liu, J., Xia, C., Wang, Y., & Zhang, L. (2023). "Is Your Code Generated by ChatGPT Really Correct? Rigorous Evaluation of Large Language Models for Code Generation (EvalPlus)." *Advances in Neural Information Processing Systems 36 (NeurIPS 2023)*. arXiv: [2305.01210](https://arxiv.org/abs/2305.01210)

### Distribution Shift & Robustness

34. Miller, J., Krauth, K., Recht, B., & Schmidt, L. (2020). "The Effect of Natural Distribution Shift on Question Answering Models." *Proceedings of the 37th International Conference on Machine Learning (ICML 2020)*. arXiv: [2004.14444](https://arxiv.org/abs/2004.14444)

35. Zhu, K., et al. (2024). "PromptBench: Towards Evaluating the Robustness of Large Language Models on Adversarial Prompts." arXiv: [2306.04528](https://arxiv.org/abs/2306.04528)

36. Nie, Y., Williams, A., Smith, E., Dziri, N., Birch, A., & Neubig, G. (2020). "Adversarial NLI: A New Benchmark for Natural Language Understanding." *Proceedings of the 58th Annual Meeting of the Association for Computational Linguistics (ACL 2020)*. arXiv: [1910.14599](https://arxiv.org/abs/1910.14599)
## References

- "Holistic Evaluation of Language Models (HELM)," Liang et al., 2023. https://arxiv.org/abs/2211.09110
- "Measuring Massive Multitask Language Understanding," Hendrycks et al., ICLR 2021. https://arxiv.org/abs/2009.03300
- "Training Verifiers to Solve Math Word Problems," Cobbe et al., 2021. https://arxiv.org/abs/2103.03874
- "Bridging the Modality Gap: Evaluating LLMs on Diverse Domains," various, 2023.
- "Chatbot Arena: An Open Platform for Evaluating LLMs by Human Preference," Zheng et al., 2023. https://arxiv.org/abs/2306.05685
- BLEU — Papineni et al., "BLEU: a Method for Automatic Evaluation of Machine Translation," ACL 2002.
- ROUGE — Lin, C.Y., "ROUGE: A Package for Automatic Evaluation of Summaries," 2004.
- BERTScore — Zhang et al., "BERTScore: Evaluating Text Generation with BERT," ICLR 2020. https://arxiv.org/abs/1904.09675
- Hugging Face Evaluate Documentation. https://huggingface.co/docs/evaluate/
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
