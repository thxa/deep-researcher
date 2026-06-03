# 03 — Dataset Collection & Creation Strategies

> A comprehensive reference for sourcing, labeling, curating, versioning, and governing datasets used in training agentic AI systems.

---

## Table of Contents

1. [Data Sources & Collection Methods](#1-data-sources--collection-methods)
2. [Data Labeling Strategies](#2-data-labeling-strategies)
3. [Dataset Quality Assessment](#3-dataset-quality-assessment)
4. [Data Preprocessing Pipelines](#4-data-preprocessing-pipelines)
5. [Data Versioning & Lineage](#5-data-versioning--lineage)
6. [Building Domain-Specific Datasets](#6-building-domain-specific-datasets)
7. [Ethical Considerations & Data Governance](#7-ethical-considerations--data-governance)
8. [Public Datasets & Benchmarks](#8-public-datasets--benchmarks)

---

## 1. Data Sources & Collection Methods

### 1.1 Full Data Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        FULL DATA PIPELINE ARCHITECTURE                         │
│                     From Raw Data to Training-Ready Artifacts                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │   WEB    │  │   APIs    │  │ SYNTHETIC │  │  CROWD    │  │  EXISTING        │  │
│  │ SCRAPING │  │  (REST/   │  │  DATA     │  │ SOURCING  │  │  DATASETS        │  │
│  │          │  │  GraphQL) │  │  GEN      │  │          │  │ (HF, Kaggle)    │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────────────┘  │
│       │             │             │             │              │                 │
│       ▼             ▼             ▼             ▼              ▼                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                     RAW DATA LAKE (Bronze Layer)                       │    │
│  │   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────────┐    │    │
│  │   │ Raw HTML │  │ JSON/API │  │ Generated │  │  Downloaded        │    │    │
│  │   │ Pages    │  │ Payloads │  │ Samples  │  │  Archives           │    │    │
│  │   └──────────┘  └──────────┘  └──────────┘  └────────────────────┘    │    │
│  └─────────────────────────────┬───────────────────────────────────────────┘    │
│                                 │                                               │
│                                 ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                   PREPROCESSING PIPELINE (Silver Layer)                │    │
│  │                                                                         │    │
│  │   ┌────────┐   ┌────────┐   ┌──────────┐   ┌──────────┐   ┌────────┐  │    │
│  │   │ DEDUP  │──▶│ CLEAN  │──▶│NORMALIZE │──▶│ TOKENIZE │──▶│FEAT.  │  │    │
│  │   │        │   │        │   │          │   │          │   │ ENG.  │  │    │
│  │   └────────┘   └────────┘   └──────────┘   └──────────┘   └────────┘  │    │
│  └─────────────────────────────┬───────────────────────────────────────────┘    │
│                                 │                                               │
│                                 ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                    LABELING & QUALITY GATE                             │    │
│  │                                                                         │    │
│  │   ┌──────────┐  ┌───────────────┐  ┌──────────┐  ┌───────────────┐    │    │
│  │   │ MANUAL   │  │ SEMI-SUPERVISED│  │  ACTIVE  │  │ PROGRAMMATIC  │    │    │
│  │   │ LABELING │  │  LABELING      │  │ LEARNING │  │  LABELING     │    │    │
│  │   └─────┬────┘  └──────┬────────┘  └────┬─────┘  └──────┬────────┘    │    │
│  │         └───────────────┼────────────────┼───────────────┘             │    │
│  │                         ▼                ▼                              │    │
│  │                  ┌──────────────────────────────┐                       │    │
│  │                  │   QUALITY ASSESSMENT          │                       │    │
│  │                  │   ┌────────────────────────┐ │                       │    │
│  │                  │   │ Completeness Check      │ │                       │    │
│  │                  │   │ Consistency Validation  │ │                       │    │
│  │                  │   │ Accuracy Benchmarking   │ │                       │    │
│  │                  │   │ Bias Detection          │ │                       │    │
│  │                  │   └────────────────────────┘ │                       │    │
│  │                  └───────────────┬───────────────┘                       │    │
│  └──────────────────────────────────┼──────────────────────────────────────┘    │
│                                     │                                           │
│                                     ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                 GOLD DATASET (Gold Layer)                              │    │
│  │                                                                         │    │
│  │   ┌───────────────┐  ┌──────────────┐  ┌────────────────────────────┐  │    │
│  │   │ Train Split   │  │ Val Split    │  │ Test Split                 │  │    │
│  │   │ 70-80%        │  │ 10-15%       │  │ 10-15%                    │  │    │
│  │   └───────────────┘  └──────────────┘  └────────────────────────────┘  │    │
│  │                                                                         │    │
│  │   ┌───────────────────────────────────────────────────────────────────┐ │    │
│  │   │ VERSION CONTROL (DVC / LakeFS / W&B)  ◄── full lineage tracked   │ │    │
│  │   └───────────────────────────────────────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### 1.2 Web Scraping

Web scraping is the automated extraction of data from web pages. It remains one of the highest-volume collection methods for NLP, vision, and multimodal datasets.

**Key Tools & Frameworks:**

| Tool | Best For | Notes |
|------|----------|-------|
| Scrapy | Large-scale crawls | Built-in dedup, middleware, pipelines |
| Beautiful Soup | Quick parses | HTML/XML; pairs with `requests` |
| Playwright / Selenium | JS-rendered pages | Headless browser automation |
| httpx + taxp | Asynchronous scraping | High throughput, async I/O |
| Apify / ScrapingBee | Managed scraping | Proxy rotation, anti-bot bypass |

**Best Practices:**

- Respect `robots.txt` and rate-limit requests (`time.sleep` / token-bucket).
- Store raw HTML before parsing — raw data is the single source of truth.
- Use content fingerprinting (SimHash / MinHash) for deduplication at the page level.
- Always set a descriptive `User-Agent`; consider publishing a contact page.
- Handle pagination, infinite scroll, and AJAX dynamically with Playwright.

```python
import scrapy

class ArticleSpider(scrapy.Spider):
    name = "articles"
    custom_settings = {
        "CONCURRENT_REQUESTS": 8,
        "DOWNLOAD_DELAY": 0.5,
        "ROBOTSTXT_OBEY": True,
        "AUTOTHROTTLE_ENABLED": True,
    }

    def start_requests(self):
        urls = open(self.urls_file).read().splitlines()
        for url in urls:
            yield scrapy.Request(url, callback=self.parse)

    def parse(self, response):
        yield {
            "url": response.url,
            "title": response.css("h1::text").get(),
            "body": " ".join(response.css("article p::text").getall()),
            "timestamp": response.headers.get("Date").decode(),
        }
```

---

### 1.3 APIs & Structured Data Sources

REST and GraphQL APIs provide structured, reliable data streams with well-defined schemas.

- **Public APIs:** Wikipedia, Hacker News, Reddit (via PRAW), GitHub, OpenAlex, Semantic Scholar.
- **GraphQL endpoints** allow precise field selection, reducing over-fetching.
- **Streaming APIs** (WebSocket, SSE) are essential for real-time data (Discord, Twitter/X firehose).

```python
import httpx

async def fetch_semantic_scholar(query: str, limit: int = 100):
    url = "https://api.semanticscholar.org/graph/v1/paper/search"
    params = {"query": query, "limit": limit, "fields": "title,abstract,year,citationCount"}
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json().get("data", [])
```

---

### 1.4 Synthetic Data Generation

Synthetic data is indispensable when real data is scarce, sensitive, or expensive to label.

**Techniques:**

1. **LLM-based generation** — Use GPT-4 / Claude / Mistral to generate instruction-response pairs, dialogues, or code examples. Filter with a judge model.
2. **Simulation environments** — Generate agent trajectories in sandboxed environments (e.g., WebArena, ToolBench).
3. **Diffusion model outputs** — For vision tasks, generate images with Stable Diffusion / DALL-E with controlled prompts.
4. **Tabular data synthesis** — CTGAN, SMOTE, or copula-based methods for structured data.
5. **Self-Instruct / Alpaca pipeline** — Seed tasks → LLM generates new tasks → filter → iterate.

```python
from openai import OpenAI

client = OpenAI()

def generate_instruction_pairs(seed_examples: list[dict], n: int = 50):
    prompt = "Generate diverse instruction-response pairs for an AI assistant.\n"
    prompt += "Seed examples:\n"
    for ex in seed_examples[:5]:
        prompt += f"Instruction: {ex['instruction']}\nResponse: {ex['response']}\n---\n"
    prompt += f"\nGenerate {n} new pairs in JSON format."

    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.9,
    )
    return completion.choices[0].message.content
```

**Quality controls for synthetic data:**

- Apply **n-gram overlap filtering** to remove near-duplicates of seed data.
- Use a **judge LLM** to score quality (1-5) and discard scores < 3.
- Maintain **distribution diversity** — bucket by topic, difficulty, response length.
- Track **synthetic provenance** metadata (model, prompt, temperature, seed).

---

### 1.5 Crowdsourcing

Crowdsourcing delegates annotation or data collection tasks to distributed workers.

- **Platforms:** Amazon Mechanical Turk (MTurk), Scale AI, Prolific, Surge AI, Remotasks.
- **Quality Control:** Gold-standard calibration questions, attention checks, majority voting, worker qualification filters (e.g., >95% approval rate, >500 HITs).
- **Cost Estimation:**

  ```
  Total Cost = (# tasks) × (# annotators per task) × (cost per annotation)
  Example: 10,000 texts × 3 annotators × $0.05 = $1,500
  ```

**Common Pitfalls:**

- Spammers / bots — filter with honeypot questions.
- Low inter-annotator agreement — refine guidelines or task design.
- Ethical pay — ensure hourly rate meets minimum wage standards.

---

### 1.6 Data Augmentation

Augmentation expands dataset diversity without collecting new samples.

| Modality | Techniques |
|----------|-----------|
| Text | Back-translation, synonym replacement (WordNet), random insertion/deletion/swap, EDA, contextual augmentation (MLM), paraphrase generation |
| Vision | Random crop/flip/rotation, color jitter, CutMix, MixUp, RandAugment, AutoAugment |
| Audio | Speed perturbation, SpecAugment, noise injection, pitch shift |
| Tabular | SMOTE, ADASYN, CTGAN |

```python
import nlpaug.augmenter.word as naw

aug = naw.SynonymAug(aug_src="wordnet")
augmented = aug.augment("The model failed to converge on the validation set.")
# → "The model failed to converge on the validation set." (or similar paraphrase)
```

---

## 2. Data Labeling Strategies

### 2.1 Labeling Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         DATA LABELING WORKFLOW                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────┐                                                                │
│  │  UNLABELED  │                                                                │
│  │    DATA     │                                                                │
│  └──────┬──────┘                                                                │
│         │                                                                       │
│         ▼                                                                       │
│  ┌──────────────────────────────────┐                                           │
│  │   LABELING STRATEGY SELECTION    │                                           │
│  │                                  │                                           │
│  │  ┌───────────────────────────────┼──────────────────────┐                   │
│  │  │              COST ◄──────────┤──────► ACCURACY       │                   │
│  │  │                               │                      │                   │
│  │  │  ┌────────────┐  ┌───────────┴───┐  ┌──────────────┐│                   │
│  │  │  │  PROGRAMMATIC│  │ SEMI-SUPERVISED│  │    MANUAL    ││                   │
│  │  │  │  LABELING   │  │   LABELING     │  │   LABELING   ││                   │
│  │  │  │  (Cheapest) │  │  (Moderate)     │  │ (Most Exp.)  ││                   │
│  │  │  └──────┬─────┘  └───────┬────────┘  └──────┬───────┘│                   │
│  │  └─────────┼────────────────┼───────────────────┼────────┘                   │
│  └────────────┼────────────────┼───────────────────┼───────────────────────────┘
│               │                │                   │                             │
│               ▼                ▼                   ▼                             │
│  ┌────────────────┐ ┌─────────────────┐ ┌──────────────────┐                   │
│  │   LABELING     │ │   LABELING      │ │   LABELING        │                   │
│  │   FUNCTIONS    │ │   FUNCTIONS +   │ │   BY EXPERTS      │                   │
│  │   ONLY         │ │   MODEL-BASED    │ │   (Veterans,      │                   │
│  │   (Snorkel)    │ │   (Self-Train)  │ │    Domain Experts)│                   │
│  └───────┬────────┘ └────────┬────────┘ └────────┬─────────┘                   │
│          │                   │                   │                               │
│          └───────────────────┼───────────────────┘                               │
│                              ▼                                                   │
│                    ┌──────────────────┐                                          │
│                    │  LABELED DATASET │                                          │
│                    │  (Raw Labels)   │                                          │
│                    └────────┬─────────┘                                          │
│                             │                                                     │
│                             ▼                                                     │
│                    ┌──────────────────┐          ┌──────────────────────┐          │
│                    │  ACTIVE LEARNING │─────────▶│  SELECT HIGH-INFO    │          │
│                    │  LOOP            │◀─────────│  SAMPLES FOR REVIEW │          │
│                    └────────┬─────────┘          └──────────────────────┘          │
│                             │                                                     │
│                             ▼                                                     │
│                    ┌──────────────────┐                                          │
│                    │  GOLD LABELS     │                                          │
│                    │  (High Quality)  │                                          │
│                    └──────────────────┘                                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### 2.2 Manual Labeling

- Hire domain experts for high-stakes tasks (medical, legal, safety).
- Provide **detailed annotation guidelines** with examples for every edge case.
- Use annotation tools: **Label Studio**, **Prodigy**, **Doccano**, **Labelbox**, **CVAT**.
- Compute **inter-annotator agreement** (Cohen's κ, Fleiss' κ, Krippendorff's α).

  | Metric | Use Case | Range |
  |--------|----------|-------|
  | Cohen's κ | 2 annotators, categorical | -1 to 1 |
  | Fleiss' κ | 3+ annotators, categorical | -1 to 1 |
  | Krippendorff's α | Any data type, any # annotators | -1 to 1 |
  | ICC | Continuous/ordinal | 0 to 1 |

- Target κ ≥ 0.7 for acceptable agreement; κ ≥ 0.8 for high-stakes domains.

---

### 2.3 Semi-Supervised Labeling

Uses a small labeled set to train a model that then pseudo-labels unlabeled data.

**Algorithms:**

- **Self-Training:** Train on labeled → predict unlabeled → add high-confidence predictions → repeat.
- **Co-Training:** Two models with different feature views teach each other.
- **Consistency Regularization:** Enforce invariance under augmentation (FixMatch, Noisy Student).
- **Pseudo-Labeling with Thresholding:** Only add predictions above confidence threshold τ (e.g., τ = 0.95).

```python
import numpy as np
from sklearn.linear_model import LogisticRegression

def self_train(X_labeled, y_labeled, X_unlabeled, threshold=0.95, max_iters=10):
    model = LogisticRegression(max_iter=1000)
    X_train, y_train = X_labeled.copy(), y_labeled.copy()

    for iteration in range(max_iters):
        model.fit(X_train, y_train)
        probas = model.predict_proba(X_unlabeled)
        max_probas = probas.max(axis=1)

        confident = max_probas >= threshold
        if not confident.any():
            break

        pseudo_labels = probas[confident].argmax(axis=1)
        X_train = np.vstack([X_train, X_unlabeled[confident]])
        y_train = np.concatenate([y_train, pseudo_labels])
        X_unlabeled = X_unlabeled[~confident]

    return model
```

---

### 2.4 Weak Supervision & Programmatic Labeling

Instead of hand-labeling every sample, encode heuristics as **labeling functions (LFs)** that vote on labels. The canonical framework is **Snorkel**.

**Labeling Function Anatomy:**

```python
from snorkel.labeling import labeling_function

@labeling_function()
def contains_question_mark(x):
    """If text contains '?', likely a question."""
    return QUESTION if "?" in x.text else ABSTAIN

@labeling_function()
def short_and_imperative(x):
    """Short sentences starting with verbs are often commands."""
    tokens = x.text.split()
    if len(tokens) < 8 and tokens[0].endswith(("e", "ify", "ate")):
        return COMMAND
    return ABSTAIN

@labeling_function()
def regex_email_pattern(x):
    """Match common email patterns in text."""
    return SPAM if re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", x.text) else ABSTAIN
```

**Snorkel Pipeline:**

1. Write LFs (10-100 per task).
2. Apply LFs to unlabeled data → build label matrix `L ∈ {0,1,...,K}^{n×m}`.
3. Learn LF accuracies and correlations using the **generative model**.
4. Combine into probabilistic training labels via the **label model**.
5. Train a discriminative model (end model) on the noisy labels.

**Advantages:** No hand-labeling needed; easy to update; extensible; captures domain knowledge.

---

### 2.5 Active Learning

Active learning selects the **most informative** unlabeled samples for human annotation, reducing total labeling cost.

**Query Strategies:**

| Strategy | Intuition | Best For |
|----------|-----------|----------|
| Uncertainty Sampling | Label samples the model is most uncertain about | Classification |
| Least Confidence | `1 - P(ŷ \| x)` | Multi-class |
| Margin Sampling | `P(y₁ \| x) - P(y₂ \| x)` | Close binary decisions |
| Entropy Sampling | `-Σ P(y \| x) log P(y \| x)` | General |
| Diversity Sampling | Maximize coverage of feature space | Budget-constrained |
| Core-Set Selection | Choose representative points (k-center) | Spatial data |
| BALD (Bayesian) | Maximize mutual information between predictions and model posterior | Deep learning |

```python
import torch
import numpy as np

def entropy_sampling(probas: np.ndarray, n_query: int) -> np.ndarray:
    """Select n_query samples with highest prediction entropy."""
    entropy = -np.sum(probas * np.log(probas + 1e-12), axis=1)
    return np.argsort(entropy)[-n_query:]

def margin_sampling(probas: np.ndarray, n_query: int) -> np.ndarray:
    """Select n_query samples with smallest margin between top-2 classes."""
    sorted_probas = np.sort(probas, axis=1)
    margin = sorted_probas[:, -1] - sorted_probas[:, -2]
    return np.argsort(margin)[:n_query]
```

---

## 3. Dataset Quality Assessment

### 3.1 Quality Assessment Flowchart

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DATA QUALITY ASSESSMENT FLOWCHART                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌──────────────────┐                                                          │
│  │  INGEST DATASET  │                                                          │
│  └────────┬─────────┘                                                          │
│           │                                                                     │
│           ▼                                                                     │
│  ┌───────────────────────────┐      ┌────────────────────────────────────┐      │
│  │   COMPLETENESS CHECK      │─────▶│  ● Missing values per column      │      │
│  │                           │      │  ● Null ratio per feature          │      │
│  │                           │      │  ● Schema validation              │      │
│  │                           │      │  ● Expected row count             │      │
│  └────────────┬──────────────┘      └────────────────────────────────────┘      │
│               │                                                                 │
│               ▼                                                                 │
│  ┌───────────────────────────┐      ┌────────────────────────────────────┐      │
│  │   CONSISTENCY CHECK       │─────▶│  ● Duplicate detection           │      │
│  │                           │      │  ● Schema conformance             │      │
│  │                           │      │  ● Value range violations         │      │
│  │                           │      │  ● Cross-field logical checks     │      │
│  └────────────┬──────────────┘      └────────────────────────────────────┘      │
│               │                                                                 │
│               ▼                                                                 │
│  ┌───────────────────────────┐      ┌────────────────────────────────────┐      │
│  │   ACCURACY CHECK          │─────▶│  ● Ground truth comparison        │      │
│  │                           │      │  ● Heuristic rule violations      │      │
│  │                           │      │  ● Annotator agreement scores     │      │
│  │                           │      │  ● Model-based validation         │      │
│  └────────────┬──────────────┘      └────────────────────────────────────┘      │
│               │                                                                 │
│               ▼                                                                 │
│  ┌───────────────────────────┐      ┌────────────────────────────────────┐      │
│  │   BIAS DETECTION          │─────▶│  ● Class distribution analysis    │      │
│  │                           │      │  ● Demographic parity check       │      │
│  │                           │      │  ● Representation audits          │      │
│  │                           │      │  ● Fairness metric evaluation      │      │
│  │                           │      │  ● Intersectional subgroup check   │      │
│  └────────────┬──────────────┘      └────────────────────────────────────┘      │
│               │                                                                 │
│               ▼                                                                 │
│  ┌─────────────────────────┐                                                    │
│  │  QUALITY REPORT          │                                                    │
│  │  ┌─────────────────────┐ │                                                    │
│  │  │ Score:  0.0 - 1.0   │ │     Scoring rubric:                               │
│  │  │                     │ │     Completeness = weighted avg of non-null %       │
│  │  │ PASS           ▶  ≥ 0.85   │                                          │
│  │  │ WARN           ▶  0.70-0.84│                                          │
│  │  │ FAIL           ▶  < 0.70  │                                           │
│  │  └─────────────────────┘ │                                                    │
│  └─────────────────────────┘                                                    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### 3.2 Completeness

```python
import pandas as pd

def completeness_report(df: pd.DataFrame) -> pd.DataFrame:
    report = pd.DataFrame({
        "column": df.columns,
        "total_rows": len(df),
        "null_count": df.isnull().sum().values,
        "null_pct": (df.isnull().sum() / len(df) * 100).round(2),
        "unique_values": df.nunique().values,
    })
    report["completeness_score"] = 1 - (report["null_count"] / report["total_rows"])
    return report.sort_values("null_pct", ascending=False)
```

### 3.3 Consistency

- **Deduplication:** Use MinHash + LSH (Locality-Sensitive Hashing) for near-duplicate detection at scale. Jaccard similarity threshold ≥ 0.8 often indicates duplicates.
- **Schema validation:** Use **Pandera**, **Great Expectations**, or **Pycroft** to enforce column types, ranges, and uniqueness constraints.
- **Cross-field rules:** e.g., `end_date > start_date`, `age ≥ 0`.

```python
import pandera as pa

schema = pa.DataFrameSchema({
    "text": pa.Column(str, pa.Check.str_length(min_value=1), nullable=False),
    "label": pa.Column(int, pa.Check.in_range(0, 9)),
    "timestamp": pa.Column("datetime64[ns]"),
    "source": pa.Column(str, pa.Check.isin(["api", "scrape", "synthetic", "crowdsource"])),
})
validated_df = schema.validate(df)
```

### 3.4 Accuracy

- Compare predictions against a held-out gold-standard set.
- Use **heuristic rules** as sanity checks (e.g., sentiment labels should match lexicon-based预估for obvious cases).
- Run a **probabilistic label model** (Snorkel) to estimate LF accuracies, or use **confident learning** (cleanlab) to find label errors.

```python
from cleanlab.classification import CleanLearning

cl = CleanLearning(clf=LogisticRegression())
cl.fit(X_train, noisy_labels_train)

label_issues = cl.find_label_issues(X_test, noisy_labels_test)
print(label_issues[label_issues["is_label_issue"]])
```

### 3.5 Bias Detection

Systematic bias in datasets can lead to unfair or harmful model behavior.

**Methods:**

1. **Distribution Analysis:** Compute class, demographic, and feature distributions.
2. **Fairness Metrics:** Demographic parity, equalized odds, calibration across subgroups.
3. **Representation Audits:** Measure over/under-representation of identity groups, languages, regions.
4. **Intersectional Analysis:** Check performance across **combinations** of attributes (e.g., gender × race).
5. **Automated Scanners:** Use **AI Fairness 360** (IBM), **Fairlearn**, or **Responsibly**.

```python
from aif360.datasets import BinaryLabelDataset
from aif360.metrics import BinaryLabelDatasetMetric

dataset = BinaryLabelDataset(df=df, label_names=["outcome"],
                              protected_attribute_names=["gender"])
metric = BinaryLabelDatasetMetric(dataset,
    unprivileged_groups=[{"gender": 0}],
    privileged_groups=[{"gender": 1}])
print(f"Disparate Impact: {metric.disparate_impact():.3f}")
print(f"Statistical Parity Difference: {metric.statistical_parity_difference():.3f}")
```

**Bias Mitigation Strategies:**

- **Resampling:** Oversample under-represented groups.
- **Reweighting:** Assign instance weights inversely proportional to group frequency.
- **Adversarial debiasing:** Train adversary to predict protected attributes from representations; penalize.
- **Data augmentation:** Generate balanced synthetic samples for minority groups.

---

## 4. Data Preprocessing Pipelines

### 4.1 Feature Engineering Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    FEATURE ENGINEERING PIPELINE                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  RAW FEATURES                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  "John Smith, 42 yrs, lives at 123 Main St, NYC. Income: $85,000/yr"  │    │
│  └────────────────────────────────┬────────────────────────────────────────┘    │
│                                   │                                             │
│  ┌────────────────────────────────▼────────────────────────────────────────┐    │
│  │                    TRANSFORMATION STAGES                               │    │
│  │                                                                        │    │
│  │  ┌──────────────┐                                                       │    │
│  │  │ 1. CLEANING  │                                                       │    │
│  │  │ ─ Strip HTML │                                                       │    │
│  │  │ ─ Remove PII │  ──▶  "John Smith, 42, lives at [REDACTED], NYC.     │    │
│  │  │ ─ Dedupe     │       Income: [REDACTED]"                             │    │
│  │  └──────┬───────┘                                                       │    │
│  │         │                                                               │    │
│  │  ┌──────▼───────┐                                                       │    │
│  │  │ 2. NORMALIZE │                                                       │    │
│  │  │ ─ Lowercase  │                                                       │    │
│  │  │ ─ Unicode NFC│  ──▶  "john smith, 42, lives at [redacted], nyc.     │    │
│  │  │ ─ Whitespace │       income: [redacted]"                            │    │
│  │  └──────┬───────┘                                                       │    │
│  │         │                                                               │    │
│  │  ┌──────▼───────┐                                                       │    │
│  │  │ 3. TOKENIZE  │                                                       │    │
│  │  │ ─ BPE / Word │  ──▶  ["john", "smith", ",", "42", ",", "lives",    │    │
│  │  │ ─ SentencePie│       "at", "[redacted]", ",", "nyc", "."]           │    │
│  │  └──────┬───────┘                                                       │    │
│  │         │                                                               │    │
│  │  ┌──────▼──────────────────────────────────────────────────────────┐    │    │
│  │  │ 4. FEATURE EXTRACTION                                          │    │    │
│  │  │                                                                 │    │    │
│  │  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐     │    │    │
│  │  │  │ Textual     │  │ Statistical  │  │ Domain-Specific    │     │    │    │
│  │  │  │ ─ TF-IDF    │  │ ─ Length     │  │ ─ NER tags         │     │    │    │
│  │  │  │ ─ BM25      │  │ ─ Freq dist  │  │ ─ POS tags         │     │    │    │
│  │  │  │ ─ Embeddings │  │ ─ Uniqueness│  │ ─ Dependency parse │     │    │    │
│  │  │  └─────────────┘  └──────────────┘  └────────────────────┘     │    │    │
│  │  └──────┬──────────────────────────────────────────────────────────┘    │    │
│  │         │                                                               │    │
│  │  ┌──────▼───────────────────┐                                          │    │
│  │  │ 5. ENCODE & SCALING      │                                          │    │
│  │  │ ─ One-hot / Label enc   │                                          │    │
│  │  │ ─ StandardScaler         │                                          │    │
│  │  │ ─ MinMax / Robust        │                                          │    │
│  │  │ ─ Embedding lookup       │                                          │    │
│  │  └──────┬───────────────────┘                                          │    │
│  │         │                                                               │    │
│  │  ┌──────▼───────────────────┐                                          │    │
│  │  │ 6. FEATURE SELECTION      │                                          │    │
│  │  │ ─ Variance threshold     │                                          │    │
│  │  │ ─ Mutual information     │                                          │    │
│  │  │ ─ L1 regularization      │                                          │    │
│  │  │ ─ SHAP importance         │                                          │    │
│  │  └────────────────────────────┘                                          │    │
│  │                                                                        │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                   │                                             │
│                                   ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │              TRAINING-READY FEATURE MATRIX                              │    │
│  │  ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐     │    │
│  │  │ f_01 │ f_02 │ f_03 │ f_04 │ f_05 │ f_06 │ ... │ f_768│ f_769│     │    │
│  │  ├──────┼──────┼──────┼──────┼──────┼──────┼──────┼──────┼──────┤     │    │
│  │  │0.012 │0.452 │0.000 │0.321 │0.871 │0.004 │ ... │0.109 │0.567 │     │    │
│  │  └──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘     │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### 4.2 Cleaning

```python
import re
import unicodedata

def clean_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"<[^>]+>", " ", text)           # strip HTML
    text = re.sub(r"https?://\S+", " ", text)      # strip URLs
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)  # strip control chars
    text = re.sub(r"\s+", " ", text).strip()        # normalize whitespace
    return text

def deduplicate_texts(texts: list[str], threshold: float = 0.8) -> list[str]:
    from datasketch import MinHash, MinHashLSH
    lsh = MinHashLSH(threshold=threshold, num_perm=128)
    unique = []
    for i, text in enumerate(texts):
        mh = MinHash(num_perm=128)
        for word in text.split():
            mh.update(word.encode("utf-8"))
        if not lsh.query(mh):
            lsh.insert(str(i), mh)
            unique.append(text)
    return unique
```

### 4.3 Normalization

- **Unicode normalization:** NFC (compose), NFD (decompose), NFKC (compatibility compose).
- **Encoding detection:** Use `chardet` or `ftfy` to fix broken Unicode.
- **Lowercasing / Truecasing:** Decide based on task — case-insensitive for search, case-sensitive for NER.
- **Number normalization:** Replace all digit sequences with a `[NUM]` token for some NLU tasks.

### 4.4 Tokenization

| Tokenizer | Mechanism | Use Case |
|-----------|-----------|----------|
| Word-level | Split on whitespace/punctuation | Traditional NLP, small vocab |
| BPE | Merge most frequent byte pairs | GPT-2/3, modern LLMs |
| WordPiece | Greedy longest-match prefix | BERT, DistilBERT |
| SentencePiece | Language-agnostic subword | mT5, XLM-R, multilingual |
| Unigram | Probabilistic subword | T5, ALBERT |

```python
from tokenizers import ByteLevelBPETokenizer

tokenizer = ByteLevelBPETokenizer()
tokenizer.train(files=["data/corpus.txt"], vocab_size=32768,
                min_frequency=2, special_tokens=["<pad>", "<s>", "</s>", "<unk>"])

encoding = tokenizer.encode("The quick brown fox jumps over the lazy dog.")
print(encoding.ids)          # token IDs
print(encoding.tokens)       # subword tokens
```

### 4.5 Feature Engineering

**Text features:** TF-IDF, BM25, character n-grams, sentence embeddings (Sentence-BERT), document embeddings (Doc2Vec, average of token embeddings).

**Numerical features:** Log transforms, polynomial features, binning, interaction features, z-score normalization.

**Temporal features:** Cyclical encoding (sin/cos for day-of-week, hour-of-day), lag features, rolling statistics.

```python
import numpy as np

def cyclical_encode(series: np.ndarray, max_val: int) -> tuple[np.ndarray, np.ndarray]:
    sin_enc = np.sin(2 * np.pi * series / max_val)
    cos_enc = np.cos(2 * np.pi * series / max_val)
    return sin_enc, cos_enc

hour_sin, hour_cos = cyclical_encode(df["hour"].values, 24)
day_sin, day_cos = cyclical_encode(df["day_of_week"].values, 7)
```

---

## 5. Data Versioning & Lineage

### 5.1 Data Versioning Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DATA VERSIONING ARCHITECTURE                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────┐      │
│  │                      REMOTE STORAGE (S3 / GCS / Azure)               │      │
│  │                                                                       │      │
│  │   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │      │
│  │   │ dataset/ │  │ dataset/ │  │ dataset/ │  │ dataset/ │           │      │
│  │   │  v1.0    │  │  v1.1    │  │  v2.0    │  │  v2.1    │           │      │
│  │   │ (203     │  │ (309     │  │ (401     │  │ (412     │           │      │
│  │   │  entries)│  │  entries)│  │  entries)│  │  entries)│           │      │
│  │   └──────────┘  └──────────┘  └──────────┘  └──────────┘           │      │
│  └──────────────────────────────────┬────────────────────────────────────┘      │
│                                      │  push / pull                          │
│                                      │                                        │
│  ┌───────────────────────────────────▼─────────────────────────────────────┐    │
│  │                       VERSION CONTROL LAYER                            │    │
│  │                                                                        │    │
│  │   ┌─────────────────┐  ┌─────────────────┐  ┌───────────────────────┐  │    │
│  │   │      DVC        │  │     LakeFS       │  │   Weights & Biases   │  │    │
│  │   │  • Git-based    │  │  • Git-like ops  │  │  • Experiment track  │  │    │
│  │   │  • .dvc files   │  │  • Branch/merge  │  │  • Artifact versioning│ │    │
│  │   │  • Pipeline DAG │  │  • Rollback      │  │  • Dataset versioning │ │    │
│  │   │  • CI/CD native │  │  • Hooks & webh. │  │  • Team collaboration│ │    │
│  │   └─────────────────┘  └─────────────────┘  └───────────────────────┘  │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                      LOCAL WORKSPACE                                    │    │
│  │                                                                        │    │
│  │   ┌──────────────────────────────────────────────────────────────┐     │    │
│  │   │  Git Repository                                             │     │    │
│  │   │  ├── .git/                                                  │     │    │
│  │   │  ├── .dvc/                                                  │     │    │
│  │   │  ├── data/                                                  │     │    │
│  │   │  │   ├── raw.dvc          ◄── points to S3 object           │     │    │
│  │   │  │   ├── processed.dvc                                      │     │    │
│  │   │  │   └── train.dvc                                          │     │    │
│  │   │  ├── dvc.yaml              ◄── pipeline stages              │     │    │
│  │   │  ├── params.yaml           ◄── hyperparameters              │     │    │
│  │   │  └── metrics.json          ◄── evaluation results           │     │    │
│  │   └──────────────────────────────────────────────────────────────┘     │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                      LINEAGE GRAPH                                      │    │
│  │                                                                        │    │
│  │   ┌────────┐     ┌───────────┐     ┌──────────┐     ┌───────────┐      │    │
│  │   │  RAW   │────▶│ PREPROCESS│────▶│  LABEL   │────▶│ SPLIT     │      │    │
│  │   │ v2.1   │     │ v2.1      │     │ v2.1     │     │ v2.1      │      │    │
│  │   └────────┘     └───────────┘     └──────────┘     └───────────┘      │    │
│  │                                            │                          │    │
│  │                                            ▼                          │    │
│  │                                     ┌───────────┐                     │    │
│  │                                     │  TRAIN    │                     │    │
│  │                                     │  v2.1     │                     │    │
│  │                                     └─────┬─────┘                     │    │
│  │                                           │                           │    │
│  │                                           ▼                           │    │
│  │                                    ┌────────────┐                     │    │
│  │                                    │ MODEL v2.1 │                     │    │
│  │                                    │ metrics    │                     │    │
│  │                                    └────────────┘                     │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

### 5.2 DVC (Data Version Control)

DVC extends Git to version large data files and ML pipelines.

```bash
# Initialize DVC
dvc init

# Track a dataset
dvc add data/raw_dataset.csv                  # creates data/raw_dataset.csv.dvc
git add data/raw_dataset.csv.dvc .gitignore
git commit -m "track raw dataset v1"

# Configure remote storage
dvc remote add -d myremote s3://my-bucket/dvc-storage

# Push data to remote
dvc push

# Define pipeline stages
dvc stage add -n preprocess \
    -d data/raw_dataset.csv -o data/processed.csv \
    python preprocess.py

dvc stage add -n train \
    -d data/processed.csv -o models/model.pkl -M metrics.json \
    python train.py

# Reproduce entire pipeline
dvc repro
```

### 5.3 LakeFS

LakeFS provides Git-like branch/merge/rollback operations on data lakes (S3, GCS, Azure).

```python
import lakefs_client

# Create a branch for experimentation
client.branches.create_branch("my-repo", branch_creation={
    "name": "experiment-new-features",
    "source": "main"
})

# Commit changes
client.commits.commit("my-repo", "experiment-new-features", commit_creation={
    "message": "Add feature-engineered columns",
    "metadata": {"feature_set": "v2"}
})

# Merge back to main after validation
client.refs.merge_into_branch("my-repo", "experiment-new-features", "main")
```

### 5.4 Weights & Biases

W&B provides experiment tracking, dataset versioning, and artifact management.

```python
import wandb

run = wandb.init(project="agentic-ai", job_type="dataset-creation")

# Log a dataset artifact
artifact = wandb.Artifact("training-data", type="dataset",
                          description="v2 training split with new features")
artifact.add_file("data/train_processed.csv")
artifact.add_dir("data/embeddings/")
run.log_artifact(artifact)

# Use a dataset in training
artifact = run.use_artifact("training-data:latest")
artifact_dir = artifact.download()
```

### 5.5 Lineage Tracking

**Full lineage** means you can trace every model prediction back to the exact version of data, code, and hyperparameters that produced it.

| Tool | Lineage Scope | Key Feature |
|------|---------------|-------------|
| DVC | Data + pipeline DAG | Reproducible pipelines |
| LakeFS | Data lake operations | Branch/merge on data |
| W&B | Experiments + artifacts | Rich visualization |
| MLflow | End-to-end ML lifecycle | Model registry |
| OpenLineage | Cross-platform standard | Passenger protocol |

---

## 6. Building Domain-Specific Datasets

### 6.1 Methodology

Building a high-quality domain-specific dataset requires domain expertise, iterative refinement, and careful curation.

**Step-by-step process:**

1. **Define the atomic unit** — What constitutes one sample? (A clinical note, a legal case, a code function, a financial transaction.)
2. **Establish inclusion/exclusion criteria** — Time range, source requirements, language, quality thresholds.
3. **Scaffold from existing datasets** — Find the closest public dataset and extend it with domain-specific labels.
4. **Iterative expert review** — Have domain experts review random samples at each iteration.
5. **Build an ontology / taxonomy** — Define the label hierarchy and relationships.
6. **Create annotation guidelines** — Detailed, with 10+ examples per label class and explicit "not sure" handling.
7. **Pilot annotation round** — 100-500 samples, compute agreement, refine guidelines.
8. **Scale annotation** — Use the refined guidelines with crowd or expert annotators.
9. **Quality audit** — Adversarial review by independent domain experts.
10. **Document everything** — Create a datasheet per Gebru et al. (2021).

### 6.2 Domain Examples

| Domain | Key Sources | Data Modalities | Label Granularity |
|--------|------------|-----------------|-------------------|
| Biomedical | PubMed, MIMIC-III, ClinicalTrials.gov | Text, tabular, imaging | UMLS codes, entity types, relations |
| Legal | Caselaw Access Project, EUR-Lex | Text | Legal categories, outcome prediction |
| Finance | SEC EDGAR, Bloomberg, Yahoo Finance | Text, time series, tabular | Sentiment, risk categories, anomaly |
| Code | GitHub, StackOverflow, The Stack | Source code, natural language | Language, task type, bug category |
| Cybersecurity | CVE, NVD, STIX | Text, logs, network flows | Vulnerability type, severity, CWE |

### 6.3 Datasheets for Datasets

Following Gebru et al. (2021), every dataset should be accompanied by a **datasheet** that answers:

- **Motivation:** Why was this dataset created? Who funded it?
- **Composition:** What does each instance represent? How many instances? Is any data missing?
- **Collection process:** How was data acquired? Who was involved? Over what timeframe?
- **Preprocessing:** What cleaning/labeling was applied? Was raw data saved?
- **Uses:** What tasks? Who shouldn't use this dataset? Are there unwanted uses?
- **Distribution:** How will it be distributed? Under what license? IP considerations?
- **Maintenance:** Who maintains it? How to report issues? Will it be updated?

---

## 7. Ethical Considerations & Data Governance

### 7.1 Ethical Framework

**Privacy:**
- **PII Detection & Removal:** Use Presidio, AWS Comprehend, or regex-based scrubbers. Redact names, emails, SSNs, phone numbers, addresses.
- **Differential Privacy:** Add calibrated noise to aggregate statistics. Use ε-differential privacy (ε = 1-10 is typical).
- **K-Anonymity:** Ensure each combination of quasi-identifiers appears in at least k records.
- **Consent & Opt-Out:** Provide clear mechanisms for data subjects to remove their data.

```python
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

text = "Patient John Doe (SSN: 123-45-6789) called on 2024-01-15."
results = analyzer.analyze(text=text, language="en")
anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
# → "Patient <PERSON> (SSN: <SSN>) called on <DATE_TIME>."
```

**Fairness:**
- Audit dataset for representation across protected attributes (gender, race, age, disability, language, region).
- Use stratified sampling to ensure balanced subgroups.
- Monitor disparate impact ratio (should be ≥ 0.8 under the "four-fifths rule").

**Transparency:**
- Publish datasheets, model cards, and data collection methodologies.
- Track all lineage from collection to deployment.
- Maintain a data fitness manifest for each dataset version.

### 7.2 Data Governance Framework

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        DATA GOVERNANCE FRAMEWORK                             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                       GOVERNANCE BOARD                              │     │
│  │  (Data stewards, Legal, Ethics, Domain experts, Engineering)        │     │
│  └──────────────────────────────┬──────────────────────────────────────┘     │
│                                 │                                            │
│         ┌───────────────────────┼───────────────────────────┐                │
│         │                       │                           │                │
│         ▼                       ▼                           ▼                │
│  ┌─────────────┐     ┌──────────────────┐     ┌────────────────────┐        │
│  │  POLICIES   │     │  COMPLIANCE      │     │  MONITORING        │        │
│  │             │     │                  │     │                    │        │
│  │ ─ Access    │     │ ─ GDPR           │     │ ─ Data lineage     │        │
│  │ ─ Retention │     │ ─ CCPA           │     │ ─ Quality metrics  │        │
│  │ ─ Sharing   │     │ ─ HIPAA          │     │ ─ Bias audits      │        │
│  │ ─ Consent   │     │ ─ SOC 2          │     │ ─ Access logs      │        │
│  │ ─ Encryption │     │ ─ Copyright     │     │ ─ Incident alerts   │        │
│  └──────┬──────┘     └────────┬─────────┘     └─────────┬──────────┘        │
│         │                     │                          │                    │
│         └─────────────────────┼──────────────────────────┘                    │
│                               │                                                │
│                               ▼                                                │
│  ┌───────────────────────────────────────────────────────────────────────┐    │
│  │                     DATA PLATFORM                                     │    │
│  │   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │    │
│  │   │ Catalog  │  │ Lineage  │  │ Quality  │  │  Access Control      │ │    │
│  │   │ (DataHub│  │ (OpenLin│  │ (Great   │  │  (Apache Ranger /    │ │    │
│  │   │  Amund.)│  │  eage)   │  │  Expect.)│  │   OPA)               │ │    │
│  │   └──────────┘  └──────────┘  └──────────┘  └──────────────────────┘ │    │
│  └───────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 7.3 Licensing Considerations

| License | Commercial Use | Modification | Attribution | Copyleft |
|---------|---------------|--------------|-------------|----------|
| CC-BY-4.0 | Yes | Yes | Yes | No |
| CC-BY-SA-4.0 | Yes | Yes (share-alike) | Yes | Yes |
| CC-BY-NC-4.0 | No | Yes | Yes | No |
| Apache 2.0 | Yes | Yes | Yes | No |
| MIT | Yes | Yes | Yes | No |
| ODbL | Yes | Yes | Yes | Yes (share-alike) |

**Critical rule:** Always verify the license of the *source* data, not just derived datasets. A dataset built by scraping a copyrighted website may not be legally redistributable even if the dataset creator applies an open license.

---

## 8. Public Datasets & Benchmarks

### 8.1 Major Hubs

| Hub | URL | Strengths |
|-----|-----|-----------|
| HuggingFace Datasets | `huggingface.co/datasets` | 100K+ datasets, streaming, deep learning integration |
| Kaggle | `kaggle.com/datasets` | Competitions, kernels, large community |
| UCI ML Repository | `archive.ics.uci.edu/ml` | Curated, small-to-medium, well-documented |
| Papers With Code | `paperswithcode.com/datasets` | Linked to SOTA benchmarks |
| OpenDataLab | `opendatalab.com` | Multimodal, Chinese-focused |
| TensorFlow Datasets | `tensorflow.org/datasets` | Seamless TF integration, standardized splits |
| Allen AI | `allenai.org/data` | NLP research datasets |
| LAION | `laion.ai` | Large-scale image-text pairs |

### 8.2 Key Benchmarks by Domain

**NLP / LLM:**

| Dataset | Task | Size | License |
|---------|------|------|---------|
| MMLU | Knowledge reasoning | 15K questions | MIT |
| HumanEval | Code generation | 164 problems | MIT |
| GSM8K | Math reasoning | 8.5K problems | MIT |
| HellaSwag | Commonsense reasoning | 40K examples | CC-BY |
| TruthfulQA | Factuality | 800 questions | CC-BY-NC |
| ARC (AI2 Reasoning Challenge) | Science QA | 7.8K questions | CC-BY |
| WMT | Machine translation | Varies per pair | Varies |
| SuperGLUE | Language understanding | 10 tasks | CC-BY |
| BigBench | Broad LLM capabilities | 200+ tasks | Apache 2.0 |

**Agentic / Tool Use:**

| Dataset | Task | Size | Notes |
|---------|------|------|-------|
| WebArena | Web navigation | 812 tasks | E-commerce, forum, CMS |
| ToolBench | API reasoning | 16K+ APIs | Multi-tool composition |
| AgentInstruct | Agent trajectories | 1,866 interactions | Diverse tool usage |
| AgentBench | Agent evaluation | 8 environments | Multi-task agent benchmark |
| OSWorld | Computer use | 369 tasks | Real OS interaction |

**Vision:**

| Dataset | Task | Size | Notes |
|---------|------|------|-------|
| ImageNet-1K | Classification | 1.28M images | Standard benchmark |
| COCO | Detection/segmentation | 330K images | Multi-task |
| ADE20K | Semantic segmentation | 25K images | 150 classes |
| LAION-5B | Image-text | 5B pairs | Web-scale |
| SA-1B (SAM) | Segmentation | 1.1B masks | Segment anything |

### 8.3 Using HuggingFace Datasets

```python
from datasets import load_dataset, DatasetDict

# Load with streaming for large datasets
dataset = load_dataset("allenai/openbookqa", streaming=True)

# Standard load
dataset = load_dataset("hellaswag")
print(dataset["train"].features)
print(dataset["train"][0])

# Create custom splits
split = dataset["train"].train_test_split(test_size=0.2, seed=42, stratify_by_column="label")

# Push your own dataset
from datasets import Dataset
my_dataset = Dataset.from_dict({"text": [...], "label": [...]})
my_dataset.push_to_hub("username/my-dataset", private=True)
```

### 8.4 Creating a Benchmark

When creating a benchmark dataset:

1. **Define the evaluation metric** before collecting data (prevent Goodhart's law).
2. **Include a leaderboard-avoidance strategy** — hold out a private test set.
3. **Publish a detailed task specification** with input/output schemas.
4. **Report baseline numbers** from existing models.
5. **Analyze difficulty distribution** — include easy, medium, and hard examples.
6. **Document limitations** and potential misuse explicitly.
7. **Follow the ROUGE/BLEU lesson** — use multiple metrics to avoid optimization against a single proxy.

---

## Appendix: Decision Matrix — Choosing a Collection Strategy

| Criterion | Web Scraping | APIs | Synthetic | Crowdsourcing | Augmentation |
|-----------|-------------|------|-----------|---------------|-------------|
| Cost | Low | Low-Medium | Medium | High | Very Low |
| Speed | Fast | Fast | Fast | Slow | Fast |
| Scale | Very High | High | Very High | Medium | Low (1-3x) |
| Quality | Variable | High | Variable | Variable | Pass-through |
| Freshness | High | Real-time | N/A | Low | Low |
| Diversity | High | Domain-limited | Limited by prompt | Depends on pool | Limited |
| Legal Risk | High | Low | Low | Low | Low |
| Best For | NLP, multimodal | Structured domains | Rare scenarios | Annotation, survey | Expanding existing |

---

## Appendix: Tooling Quick Reference

```bash
# Data pipeline orchestration
dvc run -n preprocess -d data/raw.csv -o data/clean.csv python preprocess.py

# Great Expectations validation
great_expectations suite new --_Profile

# Label Studio annotation server
label-studio start --port 8080

# Snorkel weak supervision
python -m snorkel.labeling.apply --config labeling_config.yaml

# cleanlab label error detection
python -m cleanlab.latent_estimation --model logistic_regression --data train.csv

# W&B dataset logging
wandb artifact put --name my-dataset:v1 --type dataset data/train.csv
```

---

> **Key Takeaway:** Dataset quality is the ceiling on model performance. No architecture can compensate for fundamentally flawed, biased, or insufficient data. Invest disproportionately in data — it is the highest-leverage activity in any ML project.

---

## Real References

### Data Collection & Web Scraping

1. **Halevy, A., Norvig, P., & Pereira, F.** (2009). "The Unreasonable Effectiveness of Data." *IEEE Intelligent Systems*, 24(2), 8–12. DOI: [10.1109/MIS.2009.36](https://doi.org/10.1109/MIS.2009.36)

2. **Common Crawl Foundation.** "Common Crawl: Open Repository of Web Crawl Data." URL: [https://commoncrawl.org/](https://commoncrawl.org/)

3. **Schuhmacher, M., & Ponzetto, S. P.** (2014). "Knowledge-Based Graph Document Modeling." *Proceedings of the 52nd Annual Meeting of the Association for Computational Linguistics (ACL)*, Baltimore, MD. DOI: [10.3115/v1/P14-1109](https://doi.org/10.3115/v1/P14-1109)

4. **Gao, L., et al.** (2020). "The Pile: An 800GB Dataset of Diverse Text for Language Modeling." *arXiv preprint arXiv:2101.00027*. URL: [https://arxiv.org/abs/2101.00027](https://arxiv.org/abs/2101.00027)

### Data Labeling & Annotation

6. **Ratner, A., Bach, S. H., Ehrenberg, H., Fries, J., Wu, S., & Ré, C.** (2017). "Snorkel: Rapid Training Data Creation with Weak Supervision." *Proceedings of the VLDB Endowment*, 11(3), 269–282. arXiv: [1711.10160](https://arxiv.org/abs/1711.10160). DOI: [10.14778/3157794.3157797](https://doi.org/10.14778/3157794.3157797)

7. **Settles, B.** (2012). *Active Learning*. Synthesis Lectures on Artificial Intelligence and Machine Learning, Morgan & Claypool Publishers. DOI: [10.2200/S00429ED1V01Y201207AIM018](https://doi.org/10.2200/S00429ED1V01Y201207AIM018)

8. **Snow, R., O'Connor, B., Jurafsky, D., & Ng, A. Y.** (2008). "Cheap and Fast — But Is It Good? Evaluating Non-Expert Annotations for Natural Language Tasks." *Proceedings of the 2008 Conference on Empirical Methods in Natural Language Processing (EMNLP)*, 254–263. DOI: [10.3115/1613715.1613751](https://doi.org/10.3115/1613715.1613751)

9. **Artstein, R., & Poesio, M.** (2008). "Inter-Coder Agreement for Computational Linguistics." *Computational Linguistics*, 34(4), 555–596. DOI: [10.1162/coli.07-034-R2](https://doi.org/10.1162/coli.07-034-R2)

10. **Monarch, R. M.** (2021). *Human-in-the-Loop Machine Learning: Active Learning and Annotation for Human-Centered AI*. Manning Publications. ISBN: 978-1617296741.

11. **Krizhevsky, A., Sutskever, I., & Hinton, G. E.** (2012). "ImageNet Classification with Deep Convolutional Neural Networks." *Advances in Neural Information Processing Systems (NeurIPS)*, 25. URL: [https://papers.nips.cc/paper/2012/hash/c399862d3b9d6b76c8436e924a68c45b-Abstract.html](https://papers.nips.cc/paper/2012/hash/c399862d3b9d6b76c8436e924a68c45b-Abstract.html)

### Semi-Supervised & Weak Supervision

12. **Lee, D.-H.** (2013). "Pseudo-Label: The Simple and Efficient Semi-Supervised Learning Method for Deep Neural Networks." Workshop paper, ICML 2013.

13. **Sohn, K., Berthelot, D., Carlini, N., Zhang, Z., Zhang, H., Raffel, C. A., et al.** (2020). "FixMatch: Simplifying Semi-Supervised Learning with Consistency and Confidence." *Advances in Neural Information Processing Systems (NeurIPS)*, 33. arXiv: [2001.07685](https://arxiv.org/abs/2001.07685)

14. **Xie, Q., Luong, M.-T., Hovy, E., & Le, Q. V.** (2020). "Self-Training with Noisy Student Improves ImageNet Classification." *Proceedings of the IEEE/CVF Conference on Computer Vision and Pattern Recognition (CVPR)*, 10687–10698. arXiv: [1911.04252](https://arxiv.org/abs/1911.04252)

15. **Blum, A., & Mitchell, T.** (1998). "Combining Labeled and Unlabeled Data with Co-Training." *Proceedings of the 11th Annual Conference on Computational Learning Theory (COLT)*, 92–100. DOI: [10.1145/279943.279962](https://doi.org/10.1145/279943.279962)

### Active Learning

16. **Gal, Y., Islam, R., & Ghahramani, Z.** (2017). "Deep Bayesian Active Learning with Image Data." *Proceedings of the 34th International Conference on Machine Learning (ICML)*, 1183–1192. arXiv: [1703.03221](https://arxiv.org/abs/1703.03221)

17. **Houlsby, N., Huszár, F., Ghahramani, Z., & Lengyel, M.** (2011). "Bayesian Active Learning for Classification and Preference Sensing." *Advances in Neural Information Processing Systems (NeurIPS)*, 24. (NeurIPS 2011)(https://proceedings.neurips.cc/paper/2011/hash/45c77d1a0f6f6f8e3f9c7fc2e4e8f60e-Abstract.html)

18. **Sener, O., & Savarese, S.** (2018). "Active Learning for Convolutional Neural Networks: A Core-Set Approach." *Proceedings of the 6th International Conference on Learning Representations (ICLR)*. arXiv: [1708.00489](https://arxiv.org/abs/1708.00489)

### Data Augmentation

19. **Shorten, C., & Khoshgoftaar, T. M.** (2019). "A Survey on Image Data Augmentation for Deep Learning." *Journal of Big Data*, 6, Article 60. DOI: [10.1186/s40537-019-0197-0](https://doi.org/10.1186/s40537-019-0197-0)

20. **Fadaee, M., Bisazza, A., & Monz, C.** (2017). "Data Augmentation for Low-Resource Neural Machine Translation." *Proceedings of the 55th Annual Meeting of the Association for Computational Linguistics (ACL)*, 567–573. DOI: [10.18653/v1/P17-2064](https://doi.org/10.18653/v1/P17-2064)

21. **Wei, J., & Zou, K.** (2019). "EDA: Easy Data Augmentation Techniques for Boosting Performance on Text Classification Tasks." *Proceedings of the 2019 Conference on Empirical Methods in Natural Language Processing (EMNLP)*. arXiv: [1901.11196](https://arxiv.org/abs/1901.11196)

22. **Zhang, H., Cisse, M., Dauphin, Y. N., & Lopez-Paz, D.** (2018). "mixup: Beyond Empirical Risk Minimization." *Proceedings of the 6th International Conference on Learning Representations (ICLR)*. arXiv: [1710.09412](https://arxiv.org/abs/1710.09412)

23. **Yun, S., Han, D., Oh, S. J., Chun, S., Choe, J., & Yoo, Y.** (2019). "CutMix: Regularization Strategy to Train Strong Classifiers with Localizable Features." *Proceedings of the IEEE/CVF International Conference on Computer Vision (ICCV)*, 6022–6031. arXiv: [1905.04899](https://arxiv.org/abs/1905.04899)

24. **Cubuk, E. D., Zoph, B., Shlens, J., & Le, Q. V.** (2020). "RandAugment: Practical Automated Data Augmentation with a Reduced Search Space." *Proceedings of the IEEE/CVF Conference on Computer Vision and Pattern Recognition (CVPR) Workshops*, 3008–3017. arXiv: [1909.13719](https://arxiv.org/abs/1909.13719)

25. **Park, D. S., Chan, W., Zhang, Y., & Le, Q. V.** (2019). "SpecAugment: A Simple Data Augmentation Method for Automatic Speech Recognition." *Proc. Interspeech 2019*, 2613–2617. arXiv: [1904.08779](https://arxiv.org/abs/1904.08779)

### Synthetic Data Generation

26. **Brown, T. B., Mann, B., Ryder, N., Subbiah, M., Kaplan, J., Dhariwal, P., et al.** (2020). "Language Models are Few-Shot Learners." *Advances in Neural Information Processing Systems (NeurIPS)*, 33, 1877–1901. arXiv: [2005.14165](https://arxiv.org/abs/2005.14165)

27. **Wang, Y., Kordi, Y., Mishra, S., Liu, A., Smith, N. A., Khashabi, D., et al.** (2023). "Self-Instruct: Aligning Language Models with Self-Generated Instructions." *Proceedings of the 61st Annual Meeting of the Association for Computational Linguistics (ACL)*, 1347–1363. arXiv: [2212.10560](https://arxiv.org/abs/2212.10560)

28. **Xu, L., Xie, H., Qin, S.-Z. Z., Xie, G.-S., & Wang, W.** (2023). "Parameter-Efficient Fine-Tuning of Large Language Models for Synthetic Data Generation." arXiv: [2304.09347](https://arxiv.org/abs/2304.09347)

29. **Patel, L., et al.** (2024). "Synthetic Data Generation for Large Language Models: A Survey." *arXiv preprint arXiv:2404.02609*. URL: [https://arxiv.org/abs/2404.02609](https://arxiv.org/abs/2404.02609)

### Vision & Multimodal Data

30. **He, K., Chen, X., Xie, S., Li, Y., Dollár, P., & Girshick, R.** (2022). "Masked Autoencoders Are Scalable Vision Learners." *Proceedings of the IEEE/CVF Conference on Computer Vision and Pattern Recognition (CVPR)*, 16000–16009. arXiv: [2111.06377](https://arxiv.org/abs/2111.06377). DOI: [10.1109/CVPR52688.2022.01553](https://doi.org/10.1109/CVPR52688.2022.01553)

31. **Radford, A., Kim, J. W., Hallacy, C., Ramesh, A., Goh, G., Agarwal, S., et al.** (2021). "Learning Transferable Visual Models From Natural Language Supervision." *Proceedings of the 38th International Conference on Machine Learning (ICML)*, 8748–8763. arXiv: [2103.00020](https://arxiv.org/abs/2103.00020)

32. **Schuhmann, C., Beaumont, R., Vencu, R., Gordon, C., Wightman, R., Wortsman, M., et al.** (2022). "LAION-5B: An Open Large-Scale Dataset for Training Next Generation Image-Text Models." *Advances in Neural Information Processing Systems (NeurIPS) Datasets and Benchmarks Track*. arXiv: [2210.08402](https://arxiv.org/abs/2210.08402)

33. **Kirillov, A., Mintun, E., Ravi, N., Mao, H., Rolland, C., Gustafson, L., et al.** (2023). "Segment Anything." *Proceedings of the IEEE/CVF International Conference on Computer Vision (ICCV)*, 4015–4026. arXiv: [2304.02643](https://arxiv.org/abs/2304.02643)

### Data Quality & Label Error Detection

34. **Northcutt, C. G., Athalye, A., & Mueller, J.** (2021). "Pervasive Label Errors in Test Sets Destabilize Machine Learning Benchmarks." *Proceedings of the 35th Conference on Neural Information Processing Systems (NeurIPS) Datasets and Benchmarks Track*. arXiv: [2103.14749](https://arxiv.org/abs/2103.14749)

35. **Brodley, C. E., & Friedl, M. A.** (1999). "Identifying Mislabeled Training Data." *Journal of Artificial Intelligence Research (JAIR)*, 11, 131–166. DOI: [10.1613/jair.606](https://doi.org/10.1613/jair.606)

36. **Great Expectations.** "Great Expectations: Always Know What to Expect from Your Data." Documentation: [https://docs.greatexpectations.io/](https://docs.greatexpectations.io/)

37. **Pandera.** "Pandera: Statistical Validation of Pandas Data Structures." Documentation: [https://pandera.readthedocs.io/](https://pandera.readthedocs.io/)

### Deduplication & MinHash

38. **Broder, A. Z.** (1997). "On the Resemblance and Containment of Documents." *Proceedings of the Compression and Complexity of Sequences (SEQUENCES'97)*, 21–29. DOI: [10.1109/SEQUEN.1997.666900](https://doi.org/10.1109/SEQUEN.1997.666900)

39. **Lee, K., Ippolito, D., Nystrom, A., Zhang, C., Eck, D., Callison-Burch, C., et al.** (2022). "Deduplicating Training Data Makes Language Models Better." *Proceedings of the 60th Annual Meeting of the Association for Computational Linguistics (ACL)*, 8424–8445. arXiv: [2107.06499](https://arxiv.org/abs/2107.06499)

### Bias Detection & Fairness

40. **Buolamwini, J., & Gebru, T.** (2018). "Gender Shades: Intersectional Accuracy Disparities in Commercial Gender Classification." *Proceedings of the 1st Conference on Fairness, Accountability, and Transparency (FAccT)*, PMLR Vol. 81, 77–91.

41. **Bellamy, R. K. E., Dey, K., Hind, M., Hoffman, S. C., Houde, S., Kalan, S., et al.** (2019). "AI Fairness 360: An Extensible Toolkit for Detecting, Understanding, and Mitigating Unwanted Algorithmic Bias." *arXiv preprint arXiv:1810.01943*. URL: [https://arxiv.org/abs/1810.01943](https://arxiv.org/abs/1810.01943)

42. **Bird, S., Dudík, M., Edgar, R., Horn, B., Lutz, R., Milan, V., et al.** (2020). "Fairlearn: A Toolkit for Assessing and Improving Fairness in AI." *Microsoft Research Technical Report* (MSR-TR-2020-32). URL: [https://fairlearn.org/](https://fairlearn.org/)

43. **Chawla, N. V., Bowyer, K. W., Hall, L. O., & Kegelmeyer, W. P.** (2002). "SMOTE: Synthetic Minority Over-sampling Technique." *Journal of Artificial Intelligence Research (JAIR)*, 16, 321–357. DOI: [10.1613/jair.953](https://doi.org/10.1613/jair.953)

### Crowdsourcing & Annotation Platforms

44. **Kittur, A., Chi, E. H., & Suh, B.** (2008). "Crowdsourcing User Studies with Mechanical Turk." *Proceedings of the SIGCHI Conference on Human Factors in Computing Systems (CHI)*, 453–456. DOI: [10.1145/1357054.1357127](https://doi.org/10.1145/1357054.1357127)

45. **Sheng, V. S., Provost, F., & Ipeirotis, P. G.** (2008). "Get Another Label? Improving Data Quality and Data Mining Using Multiple, Noisy Labelers." *Proceedings of the 14th ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*, 614–622. DOI: [10.1145/1401890.1401965](https://doi.org/10.1145/1401890.1401965)

46. **Dow, S., Kulkarni, A., Klemmer, S., & Hartmann, B.** (2012). "Shepherding the Crowd Yields Better Work." *Proceedings of the SIGCHI Conference on Human Factors in Computing Systems (CHI)*, 1669–1672. DOI: [10.1145/2207676.2208277](https://doi.org/10.1145/2207676.2208277)

### Data Versioning & MLOps Tools

47. **DVC Organization.** "DVC: Data Version Control — Git for Data & ML Experiments." Documentation: [https://dvc.org/doc](https://dvc.org/doc)

48. **Weights & Biases.** "W&B Documentation." URL: [https://docs.wandb.ai/](https://docs.wandb.ai/)

49. **LakeFS.** "lakeFS: Data Version Control for Your Data Lake." Documentation: [https://docs.lakefs.io/](https://docs.lakefs.io/)

50. **Zaharia, M., et al.** (2023). "The Shift from Models to Compound AI Systems." *Berkeley AI Research Blog*. URL: [https://bair.berkeley.edu/blog/2024/02/18/compound-ai-systems/](https://bair.berkeley.edu/blog/2024/02/18/compound-ai-systems/)

### Tokenization & Preprocessing

51. **Sennrich, R., Haddow, B., & Birch, A.** (2016). "Neural Machine Translation of Rare Words with Subword Units." *Proceedings of the 54th Annual Meeting of the Association for Computational Linguistics (ACL)*, 1715–1725. arXiv: [1508.07909](https://arxiv.org/abs/1508.07909)

52. **Kudo, T., & Richardson, J.** (2018). "SentencePiece: A Simple and Language Independent Approach to Neural Text Processing." *Proceedings of the 2018 Conference on Empirical Methods in Natural Language Processing (EMNLP): Demonstration*, 66–71. arXiv: [1808.06226](https://arxiv.org/abs/1808.06226)

53. **Kudo, T.** (2018). "Subword Regularization: Improving Neural Network Translation Models with Multiple Subword Candidates." *Proceedings of the 56th Annual Meeting of the Association for Computational Linguistics (ACL)*, 66–75. arXiv: [1804.10959](https://arxiv.org/abs/1804.10959)

### Data Governance, Ethics & Privacy

54. **Gebru, T., Morgenstern, J., Vecchione, B., Vaughan, J. W., Wallach, H., Daumé III, H., & Crawford, K.** (2021). "Datasheets for Datasets." *Communications of the ACM*, 64(12), 86–92. DOI: [10.1145/3458723](https://doi.org/10.1145/3458723). Originally arXiv: [1803.09010](https://arxiv.org/abs/1803.09010)

55. **Dwork, C., & Roth, A.** (2014). "The Algorithmic Foundations of Differential Privacy." *Foundations and Trends in Theoretical Computer Science*, 9(3–4), 211–407. DOI: [10.1561/0400000042](https://doi.org/10.1561/0400000042)

56. **Sweeney, L.** (2002). "k-Anonymity: A Model for Protecting Privacy." *International Journal of Uncertainty, Fuzziness and Knowledge-Based Systems*, 10(5), 557–570. DOI: [10.1142/S0218488502001648](https://doi.org/10.1142/S0218488502001648)

57. **Mitchell, M., Wu, S., Zaldivar, A., Barnes, P., Vasserman, L., Hutchinson, B., et al.** (2019). "Model Cards for Model Reporting." *Proceedings of the Conference on Fairness, Accountability, and Transparency (FAccT)*, 220–229. DOI: [10.1145/3287560.3287596](https://doi.org/10.1145/3287560.3287596)

58. **Bender, E. M., & Friedman, B.** (2018). "Data Statements for Natural Language Processing: Toward Mitigating Systemic Language Variation Bias." *Proceedings of the 2018 Conference on Empirical Methods in Natural Language Processing (EMNLP): Tutorial*, 4–11. DOI: [10.18653/v1/W18-5802](https://doi.org/10.18653/v1/W18-5802)

59. **Microsoft Research.** "Presidio: Data Protection and PII Anonymization Engine." Documentation: [https://microsoft.github.io/presidio/](https://microsoft.github.io/presidio/)

### Agentic AI Datasets & Benchmarks

60. **Zhou, S., Xu, F. F., Zhu, H., Zhou, X., Lo, R., et al.** (2024). "WebArena: A Realistic Web Environment for Building Autonomous Agents." *International Conference on Learning Representations (ICLR)*. arXiv: [2307.13854](https://arxiv.org/abs/2307.13854)

61. **Qin, Y., Liang, S., Ye, Y., Zhu, K., Yan, L., Lu, Y., et al.** (2024). "ToolLLM: Facilitating Large Language Models to Master 16000+ Real-world APIs." *International Conference on Learning Representations (ICLR)*. arXiv: [2307.16789](https://arxiv.org/abs/2307.16789)

62. **Xue, F., et al.** (2024). "AgentInstruct: Toward Generative AI in a Simulated World." *arXiv preprint arXiv:2405.14531*. URL: [https://arxiv.org/abs/2405.14531](https://arxiv.org/abs/2405.14531)

63. **Liu, X., et al.** (2023). "AgentBench: Evaluating LLMs as Agents." *Proceedings of the 12th International Conference on Learning Representations (ICLR)*. arXiv: [2310.02483](https://arxiv.org/abs/2310.02483)

64. **Xue, T., et al.** (2024). "OSWorld: Benchmarking Multimodal Agents for Open-Ended Tasks in Real Computer Environments." *arXiv preprint arXiv:2404.07972*. URL: [https://arxiv.org/abs/2404.07972](https://arxiv.org/abs/2404.07972)

### Datasets & Open Data Platforms

65. **Lhoest, Q., del Moral, A. F., Jernite, Y., Ramaswamy, A., Raff, E., Sileo, L., et al.** (2021). "Datasets: A Community Library for Natural Language Processing." *Proceedings of the 2021 Conference on Empirical Methods in Natural Language Processing (EMNLP): System Demonstrations*, 175–184. DOI: [10.18653/v1/2021.emnlp-demo.21](https://doi.org/10.18653/v1/2021.emnlp-demo.21). Documentation: [https://huggingface.co/docs/datasets](https://huggingface.co/docs/datasets)

66. **Bojar, O., Buck, C., Federmann, C., Haddow, B., Koehn, P., Leveling, J., et al.** (2014). "Findings of the 2014 Workshop on Statistical Machine Translation." *Proceedings of the Ninth Workshop on Statistical Machine Translation*, 12–58. DOI: [10.3115/v1/W14-3302](https://doi.org/10.3115/v1/W14-3302)

67. **Wang, A., Pruksachatkun, Y., Nangia, N., Singh, A., Michael, S., Hill, F., et al.** (2019). "SuperGLUE: A Stickier Benchmark for General-Purpose Language Understanding Systems." *Advances in Neural Information Processing Systems (NeurIPS)*, 32. arXiv: [1905.00537](https://arxiv.org/abs/1905.00537)

### Tabular Data Synthesis

68. **Xu, L., Skoularidou, M., Cuesta-Infante, A., & Veeramachaneni, K.** (2019). "Modeling Tabular Data Using Conditional GAN." *Advances in Neural Information Processing Systems (NeurIPS)*, 32. arXiv: [1907.00503](https://arxiv.org/abs/1907.00503)

69. **He, H., Bai, Y., Garcia, E. A., & Li, S.** (2008). "ADASYN: Adaptive Synthetic Sampling Approach for Imbalanced Learning." *Proceedings of the IEEE International Joint Conference on Neural Networks (IJCNN)*, 1322–1328. DOI: [10.1109/IJCNN.2008.4633969](https://doi.org/10.1109/IJCNN.2008.4633969)
## References

- Hugging Face Datasets Documentation. https://huggingface.co/docs/datasets/
- "Datasheets for Datasets," Gebru et al., NeurIPS 2021. https://arxiv.org/abs/1803.09010
- "Data and its (Dis)Contents: A Survey of Dataset Curation," Roggio et al., 2023.
- Common Crawl — Open web crawl data. https://commoncrawl.org/
- The Pile: An 800GB Dataset of Diverse Text, Gao et al., 2020. https://arxiv.org/abs/2101.00027
- RedPajama — Open source LLM training data. https://www.together.ai/blog/redpajama
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
- "Scaling Data-Constrained Language Models," Muennighoff et al., 2023. https://arxiv.org/abs/2305.16264
- "Quality of AI Training Data Matters," various, Anthropic Research, 2023.
- WUDAO (悟道) — Chinese large-scale pretraining dataset. https://data.baai.ac.cn/
