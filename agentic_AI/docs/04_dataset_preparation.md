# Dataset Preparation and Engineering: A Comprehensive Guide

> "Garbage in, garbage out" is not merely a platitude—it is the immutable law of machine learning. Every model's ceiling is set before the first forward pass, by the quality of its training data.

---

## Table of Contents

1. [Advanced Data Cleaning](#1-advanced-data-cleaning)
2. [Data Transformation Strategies](#2-data-transformation-strategies)
3. [Train/Val/Test Splitting Strategies](#3-trainvaltest-splitting-strategies)
4. [Data Augmentation Techniques](#4-data-augmentation-techniques)
5. [Building Robust Data Pipelines](#5-building-robust-data-pipelines)
6. [Data Cataloging and Metadata Management](#6-data-cataloging-and-metadata-management)
7. [Handling Imbalanced Datasets](#7-handling-imbalanced-datasets)
8. [Data Privacy](#8-data-privacy)

---

## 1. Advanced Data Cleaning

### 1.1 Outlier Detection

Outliers distort statistics, inflate loss, and destabilize gradients. Detect them before they detect you.

**Statistical Methods:**

| Method | Best For | Assumption |
|--------|----------|------------|
| Z-score | Univariate, normal-ish distributions | Approximate normality |
| Modified Z-score (MAD) | Heavy-tailed distributions | Median robustness |
| IQR (Tukey's fences) | Skewed distributions | No distributional assumption |
| Grubbs' test | Single outlier in univariate data | Normality |
| Mahalanobis distance | Multivariate outliers | Multivariate normality |

```python
import numpy as np
from scipy import stats

def zscore_outliers(data, threshold=3.5):
    z = np.abs(stats.zscore(data, nan_policy='omit'))
    return z > threshold

def modified_zscore_outliers(data, threshold=3.5):
    median = np.nanmedian(data)
    mad = stats.median_abs_deviation(data, nan_policy='omit')
    modified_z = 0.6745 * (data - median) / (mad + 1e-10)
    return np.abs(modified_z) > threshold

def iqr_outliers(data, factor=1.5):
    q1, q3 = np.nanpercentile(data, [25, 75])
    iqr = q3 - q1
    lower, upper = q1 - factor * iqr, q3 + factor * iqr
    return (data < lower) | (data > upper)
```

**Model-Based Methods:**

- **Isolation Forest:** Randomly partitions features; anomalies isolate faster (fewer splits). Works on high-dimensional data. Scale with `n_estimators` and `contamination`.
- **Local Outlier Factor (LOF):** Compares local density of a point to its neighbors. Points in sparse regions relative to their neighbors are outliers. Captures local context global methods miss.
- **One-Class SVM:** Learns a decision boundary around "normal" data in feature space (via RBF kernel). Best when you have clean normal data for training.
- **Autoencoder Reconstruction Error:** Train on normal data; high reconstruction error flags outliers. Captures nonlinear relationships. The bottleneck forces the model to learn a compressed representation of normal patterns.

```python
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

iso_forest = IsolationForest(
    n_estimators=200,
    contamination=0.01,
    max_samples='auto',
    random_state=42
)
outlier_mask = iso_forest.fit_predict(X) == -1

lof = LocalOutlierFactor(n_neighbors=20, contamination=0.01)
outlier_mask = lof.fit_predict(X) == -1
```

### 1.2 Missing Data Imputation

Not all missing data is equal. The mechanism of missingness dictates your strategy:

| Mechanism | Definition | Strategy |
|-----------|-----------|----------|
| MCAR | Missing completely at random | Simple imputation is unbiased |
| MAR | Missing at random (conditional on observed) | Model-based imputation |
| MNAR | Missing not at random (depends on unobserved) | Domain-specific handling required |

**Progression of Imputation Techniques:**

```python
# Level 1: Simple — fast, biased, sometimes adequate
from sklearn.impute import SimpleImputer
mean_imputer = SimpleImputer(strategy='mean')     # Numeric
mode_imputer = SimpleImputer(strategy='most_frequent')  # Categorical
constant_imputer = SimpleImputer(strategy='constant', fill_value='UNKNOWN')

# Level 2: KNN — captures local structure, O(n^2) memory
from sklearn.impute import KNNImputer
knn_imputer = KNNImputer(n_neighbors=5, weights='distance')

# Level 3: Iterative (MICE) — models each feature conditionally
from sklearn.experimental import enable_iterative_imputer
from sklearn.impute import IterativeImputer
mice_imputer = IterativeImputer(
    estimator=BayesianRidge(),
    max_iter=10,
    random_state=42,
    sample_posterior=True   # uncertainty quantification
)

# Level 4: Deep learning — for complex nonlinear relationships
# Use autoencoders or VAEs trained on observed values
# Denoising autoencoders naturally learn to fill missing values
```

**Critical rule:** Always create an indicator column (`was_missing`) before imputation. The fact that a value was missing is often itself a powerful signal.

### 1.3 Deduplication

Duplicate data causes silent overfitting—the model memorizes repeated examples and overestimates its generalization.

**Exact Deduplication:**
```python
# Row-level
df = df.drop_duplicates()

# Hash-based for large datasets
import hashlib
seen = set()
unique_rows = []
for row in df.itertuples(index=False):
    h = hashlib.md5(str(row).encode()).hexdigest()
    if h not in seen:
        seen.add(h)
        unique_rows.append(row)
```

**Fuzzy Deduplication (near-duplicates):**

```python
from datasketch import MinHash, MinHashLSH

def minhash_dedup(texts, num_perm=128, threshold=0.8):
    lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    for i, text in enumerate(texts):
        mh = MinHash(num_perm=num_perm)
        for token in text.split():
            mh.update(token.encode('utf8'))
        lsh.insert(f"doc_{i}", mh)

    clusters = []
    assigned = set()
    for i, text in enumerate(texts):
        if f"doc_{i}" in assigned:
            continue
        mh = MinHash(num_perm=num_perm)
        for token in text.split():
            mh.update(token.encode('utf8'))
        similar = lsh.query(mh)
        clusters.append(similar)
        assigned.update(similar)
    return clusters
```

**For NLP datasets**, also check for:
- **N-gram overlap**: Detect documents with >80% n-gram overlap.
- **Suffix/prefix deduplication**: Remove documents that are substrings of others.
- **SemDeDup**: Use embedding-space distance (e.g., cosine similarity in a pretrained model's representation) to find semantic duplicates.

---

## 2. Data Transformation Strategies

### 2.1 Feature Scaling

| Method | Formula | Use When | Sensitive to Outliers |
|--------|---------|----------|-----------------------|
| Min-Max | `(x - min) / (max - min)` | Bounded features, neural nets | Yes |
| Standard (Z-score) | `(x - mean) / std` | Linear models, SVM, PCA | Moderately |
| Robust | `(x - median) / IQR` | Heavy outliers present | No |
| Log | `log(x + c)` | Right-skewed, monetory data | No |
| Power (Yeo-Johnson) | MLE-based transform | Making distributions Gaussian-ish | No |

```python
from sklearn.preprocessing import StandardScaler, RobustScaler, PowerTransformer

scaler = RobustScaler()           # safe default
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)    # reuse train statistics!
```

**Pitfall:** Always `fit` on training data only, then `transform` both train and test. Fitting on the full dataset leaks test distribution information.

### 2.2 Encoding Categorical Variables

```
Low Cardinality (<=15 levels)     │  High Cardinality (>15 levels)
  ├─ One-Hot Encoding             │    ├─ Target Encoding (with CV smoothing)
  │   → sparse, no ordinality     │    │  (mean-replace with leave-one-out)
  ├─ Ordinal Encoding             │    ├─ Frequency/Count Encoding
  │   → only if genuine order     │    │  (replace with occurrence count)
  └─ Binary Encoding              │    ├─ Hashing Encoding
      → compromise sparsity/order │    │  (fixed-dimension, collisions OK)
                                  │    └─ Embedding (learned per-category)
                                  │       → best for deep learning
```

```python
import category_encoders as ce
from sklearn.model_selection import KFold

# Target encoding with proper regularization
target_enc = ce.TargetEncoder(
    cols=['city', 'product_id'],
    smoothing=1.0   # higher smoothing = more regularization toward global mean
)

# Fit on train folds only to prevent target leakage
kf = KFold(n_splits=5, shuffle=True, random_state=42)
X_train_encoded = X_train.copy()
for train_idx, val_idx in kf.split(X_train):
    target_enc.fit(X_train.iloc[train_idx], y_train.iloc[train_idx])
    X_train_encoded.iloc[val_idx] = target_enc.transform(X_train.iloc[val_idx])
```

### 2.3 Learned Embeddings

For high-cardinality categoricals in neural networks, treat each category as a discrete token and learn an embedding table:

```python
import torch
import torch.nn as nn

class CategoricalEmbedding(nn.Module):
    def __init__(self, cardinality, embed_dim):
        super().__init__()
        # Rule of thumb: embed_dim = min(cardinality^0.25 * 4, 600)
        self.embedding = nn.Embedding(cardinality, embed_dim)
        nn.init.xavier_uniform_(self.embedding.weight)

    def forward(self, x):
        return self.embedding(x)
```

**Embedding dimension heuristic:** `dim = min(4 * cardinality^(1/4), 600)`. A category with 10,000 levels → `4 * 10 = 40`-dimensional embedding.

---

## 3. Train/Val/Test Splitting Strategies

### ASCII Art: Cross-Validation Strategies Comparison

```
┌─────────────────────────────────────────────────────────────────────┐
│                CROSS-VALIDATION STRATEGIES COMPARISON                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. K-FOLD (Standard)                                              │
│     Fold 1: [VAL][████████████████████████████████████████████]    │
│     Fold 2: [████████][VAL][████████████████████████████████]      │
│     Fold 3: [████████████████][VAL][████████████████████████]      │
│     Fold 4: [████████████████████████][VAL][████████████████]      │
│     Fold 5: [████████████████████████████████][VAL][████████]      │
│     → Random partition, good for iid data                          │
│                                                                     │
│  2. STRATIFIED K-FOLD                                              │
│     Fold 1: [AaAa][BbBb][AaAa][BbBb][AaAa][BbBb][AaAa][BbBb]      │
│     Fold 2: [AaAa][BbBb][AaAa][BbBb][AaAa][BbBb][AaAa][BbBb]      │
│             Each fold preserves class ratio (α:β ≈ original)       │
│     → MUST USE for imbalanced classification                        │
│                                                                     │
│  3. TIME SERIES (Expanding Window)                                 │
│     Fold 1: [TRAIN───────────][VAL]                                │
│     Fold 2: [TRAIN────────────────────][VAL]                       │
│     Fold 3: [TRAIN──────────────────────────────][VAL]             │
│             → Never use future to predict past                      │
│             → Preserves temporal causality                          │
│                                                                     │
│  4. GROUP K-FOLD                                                   │
│     Group A: [■■■■■■■■]  Group B: [●●●●●●●●]  Group C: [▲▲▲▲▲▲]   │
│     Fold 1: [■■■■■■■■][●●●●●●●●]  [VAL=▲▲▲▲▲▲]                   │
│     Fold 2: [■■■■■■■■][▲▲▲▲▲▲]    [VAL=●●●●●●●●]                  │
│     Fold 3: [●●●●●●●●][▲▲▲▲▲▲]    [VAL=■■■■■■■■]                  │
│     → All samples from one group stay in same fold                  │
│     → CRITICAL for: medical (patient), NLP (document), ad (user)   │
│                                                                     │
│  5. NESTED CV (Hyperparameter Selection)                           │
│     ┌──────── Outer Fold 1 ────────┐                                │
│     │  ┌─ Inner Fold 1.1 ─┐       │                                │
│     │  │  Train    Val      │ Test  │                                │
│     │  │  [████][██]        │ [██]  │                                │
│     │  ├─ Inner Fold 1.2 ─┤       │                                │
│     │  │  [████████][██]    │ [██]  │                                │
│     │  └───────────────────┘       │                                │
│     ┌──────── Outer Fold 2 ────────┐                                │
│     │     ...repeat...             │                                │
│     → Unbiased estimate of generalization error                      │
│     → Outer loop: evaluation, Inner loop: model selection            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

     Strategy              When to Use                    Pitfall if Wrong
     ──────────            ──────────                    ─────────────────
     K-Fold               IID, balanced data            Data leakage across folds
     Stratified K-Fold    Classification, imbalance      Skewed fold distributions
     Time Series Split     Temporal/sequential data      Look-ahead bias
     Group K-Fold          Non-IID groups (users/patients) Overoptimistic validation
     Nested CV            Model selection + evaluation   Computationally expensive
     Repeated K-Fold      Small datasets                Still leaks if non-IID
```

### Splitting Implementation

```python
from sklearn.model_selection import (
    StratifiedKFold, GroupKFold, TimeSeriesSplit, RepeatedStratifiedKFold
)

X, y, groups = load_data()

# Stratified — for classification
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
for train_idx, val_idx in skf.split(X, y):
    X_train, X_val = X[train_idx], X[val_idx]

# Group — prevent leakage across entities
gkf = GroupKFold(n_splits=5)
for train_idx, val_idx in gkf.split(X, y, groups=groups):
    X_train, X_val = X[train_idx], X[val_idx]

# Time-series — expanding window
tscv = TimeSeriesSplit(n_splits=5)
for train_idx, val_idx in tscv.split(X):
    X_train, X_val = X[train_idx], X[val_idx]

# Nested CV — for unbiased model selection
outer_cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
inner_cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
for train_idx, test_idx in outer_cv.split(X, y):
    # Inner loop: hyperparameter search
    grid_search = GridSearchCV(model, param_grid, cv=inner_cv)
    grid_search.fit(X[train_idx], y[train_idx])
    # Outer loop: evaluate best model
    score = grid_search.score(X[test_idx], y[test_idx])
```

**The golden rule:** Your validation scheme must mirror the production evaluation. If production predicts the future, validate on the future. If production generalizes to new users, validate on held-out users.

---

## 4. Data Augmentation Techniques

### ASCII Art: Data Augmentation Strategy Decision Tree

```
                        ┌──────────────────────┐
                        │  WHAT IS YOUR DATA?   │
                        └──────────┬───────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
       ┌──────▼──────┐     ┌──────▼──────┐      ┌───────▼───────┐
       │   IMAGES     │     │    TEXT     │      │  TABULAR/AUDIO │
       └──────┬──────┘     └──────┬──────┘      └───────┬───────┘
              │                    │                     │
    ┌─────────┴─────────┐  ┌──────┴──────┐     ┌───────┴────────┐
    │ Task sensitivity?  │  │ Preserve    │     │ Class balance?  │
    │                    │  │ semantics?  │     │                 │
    ├─ Geometric:        │  │             │     ├─ Imbalanced:    │
    │  ├ flip (H/V)      │  ├─ YES:      │     │  ├ SMOTE        │
    │  ├ rotate (±15°)   │  │  ├ synonym   │     │  ├ ADASYN       │
    │  ├ translate        │  │  ├ back-trans│     │  ├ mixup (reg)  │
    │  ├ crop/zoom        │  │  └ contextual│     │  └ noise inj.   │
    │  └ elastic deform  │  │    replace   │     │                  │
    │                    │  │             │     ├─ Balanced:       │
    ├─ Photometric:      │  ├─ NO (robust):│    │  ├ jiteur       │
    │  ├ color jitter    │  │  ├ random    │     │  ├ swap columns │
    │  ├ brightness/cont │  │  │  erase     │     │  └ dropout feat│
    │  ├ Gaussian noise   │  │  ├ random    │     └────────────────┘
    │  └ blur/sharpen    │  │  │  insert    │
    │                    │  │  └ word       │
    ├─ Mixing:            │  │     shuffle  │
    │  ├ MixUp            │  │             │
    │  │  λxᵢ+(1-λ)xⱼ   │  └─ Paraphrase │
    │  │  λyᵢ+(1-λ)yⱼ   │     models/API  │
    │  ├ CutMix           │                  │
    │  │  patch replace  │  ┌──────────────┴───────┐
    │  │  label mix prop │  │  ADVANCED (All domains)│
    │  └ Mosaic          │  │                        │
    │     4-img collage   │  ├─ Adversarial:          │
    │                    │  │  FGSM/PGD examples      │
    └─ Caution:          │  │  (robustness)           │
      Digit '6' ↔ '9'!  │  ├─ Generative:            │
      Flip may invert    │  │  GANs, diffusion, VAEs  │
      semantic meaning   │  │  (synthetic diversity)  │
                         │  └─ Curriculum:            │
                         │     easy→hard scheduling   │
                         └────────────────────────────┘
```

### 4.1 Image Augmentation

```python
import albumentations as A
from albumentations.pytorch import ToTensorV2

train_transform = A.Compose([
    A.RandomResizedCrop(224, 224, scale=(0.8, 1.0)),
    A.HorizontalFlip(p=0.5),
    A.ShiftScaleRotate(shift_limit=0.1, scale_limit=0.1, rotate_limit=15, p=0.5),
    A.OneOf([
        A.GaussNoise(var_limit=(10, 50)),
        A.GaussianBlur(blur_limit=3),
        A.MotionBlur(blur_limit=3),
    ], p=0.3),
    A.OneOf([
        A.CLAHE(clip_limit=2),
        A.RandomBrightnessContrast(brightness_limit=0.2, contrast_limit=0.2),
        A.HueSaturationValue(hue_shift_limit=10, sat_shift_limit=20),
    ], p=0.3),
    A.CoarseDropout(max_holes=8, max_height=16, max_width=16, p=0.3),
    A.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ToTensorV2(),
])
```

**MixUp and CutMix implementations:**

```python
import torch
import torch.nn.functional as F

def mixup_data(x, y, alpha=0.4):
    lam = np.random.beta(alpha, alpha)
    batch_size = x.size(0)
    index = torch.randperm(batch_size, device=x.device)
    mixed_x = lam * x + (1 - lam) * x[index]
    y_a, y_b = y, y[index]
    return mixed_x, y_a, y_b, lam

def cutmix_data(x, y, alpha=1.0, beta=1.0):
    lam = np.random.beta(alpha, beta)
    batch_size = x.size(0)
    index = torch.randperm(batch_size, device=x.device)

    W, H = x.size(2), x.size(3)
    cut_rat = np.sqrt(1.0 - lam)
    cut_w, cut_h = int(W * cut_rat), int(H * cut_rat)
    cx, cy = np.random.randint(W), np.random.randint(H)
    x1, y1 = np.clip(cx - cut_w // 2, 0, W), np.clip(cy - cut_h // 2, 0, H)
    x2, y2 = np.clip(cx + cut_w // 2, 0, W), np.clip(cy + cut_h // 2, 0, H)

    x_clone = x.clone()
    x_clone[:, :, x1:x2, y1:y2] = x[index, :, x1:x2, y1:y2]
    lam = 1 - (x2 - x1) * (y2 - y1) / (W * H)
    return x_clone, y, y[index], lam

def mixup_criterion(criterion, pred, y_a, y_b, lam):
    return lam * criterion(pred, y_a) + (1 - lam) * criterion(pred, y_b)
```

### 4.2 Text Augmentation

```python
import nlpaug.augmenter.word as naw

# Back-translation (preserves semantics best)
back_translation = naw.BackTranslationAug(
    from_model_name='facebook/wmt19-en-de',
    to_model_name='facebook/wmt19-de-en'
)
augmented = back_translation.augment("The model generalizes well on unseen data.")

# Synonym replacement (fast, local)
synonym_aug = naw.SynonymAug(aug_src='wordnet')
augmented = synonym_aug.augment("The model generalizes well on unseen data.")

# Contextual word insertion (BERT-powered)
contextual_aug = naw.ContextualAugAug(
    model_path='bert-base-uncased',
    action='substitute'
)
augmented = contextual_aug.augment("The model generalizes well on unseen data.")

# Random deletion (regularization)
def random_deletion(text, p=0.1):
    words = text.split()
    return ' '.join([w for w in words if random.random() > p]) or words[0]

# Random swap
def random_swap(text, n=1):
    words = text.split()
    for _ in range(n):
        i, j = random.sample(range(len(words)), 2)
        words[i], words[j] = words[j], words[i]
    return ' '.join(words)
```

### 4.3 Tabular Augmentation (SMOTE)

```python
from imblearn.over_sampling import SMOTE, ADASYN, BorderlineSMOTE
from imblearn.combine import SMOTETomek

# Standard SMOTE — linear interpolation between minority samples
smote = SMOTE(sampling_strategy='auto', k_neighbors=5, random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train, y_train)

# BorderlineSMOTE — focus on borderline minority samples
bl_smote = BorderlineSMOTE(kind='borderline-1', random_state=42)
X_resampled, y_resampled = bl_smote.fit_resample(X_train, y_train)

# SMOTE + Tomek (oversample minority, then clean borderline majority)
smote_tomek = SMOTETomek(random_state=42)
X_resampled, y_resampled = smote_tomek.fit_resample(X_train, y_train)
```

**SMOTE visualized:**
```
  Original (imbalanced)          After SMOTE
  ○ ○ ○ ○ ○ ○ ○ ○ ○          ○ ○ ○ ○ ○ ○ ○ ○ ○
  ○ ○ ○ ○ ○ ○ ○ ○ ○          ○ ○ ○ ○ ○ ○ ○ ○ ○
  ○ ○ ○ ○ ○ ○ ○ ○ ○          ○ ○ ○ ○ ○ ○ ○ ○ ○
  ○ ○ ○ ○ ○ ○ ○ ○ ○          ○ ○ ○ ○ ○ ○ ○ ○ ○
        ● ● ●                       ● ◐ ● ◐ ● ◐ ● ◐
      ● ● ●                         ◐ ● ◐ ● ◐ ● ◐ ● ◐
        ●                            ● ◐ ● ◐
  ○ = majority (100)              ○ = majority (100)
  ● = minority (5)                ● ● ◐ = minority (20)
  ◐ = synthetic samples generated along lines
      between k-nearest minority neighbors
```

---

## 5. Building Robust Data Pipelines

### ASCII Art: Data Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     DATA PIPELINE ARCHITECTURE                              │
│                                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │  INGEST   │───▶│   VALIDATE   │───▶│   TRANSFORM  │───▶│    OUTPUT    │ │
│  │          │    │              │    │              │    │              │ │
│  │ Sources:  │    │ Schema check │    │ Clean        │    │ Train shards │ │
│  │ • S3/GCS  │    │ Type check   │    │ Impute       │    │ Val shards   │ │
│  │ • DB dump │    │ Range check  │    │ Encode       │    │ Test shards   │ │
│  │ • API      │    │ Null check   │    │ Scale        │    │ Manifest     │ │
│  │ • Stream  │    │ Duplicate    │    │ Augment      │    │ Stats/Report │ │
│  │ • CSV/Par │    │ Distribution  │    │ Split        │    │              │ │
│  └──────────┘    └──────┬───────┘    └──────┬───────┘    └──────────────┘ │
│                          │                    │                           │
│  Tools:                  │  Tools:            │  Tools:                   │
│  ┌─────────────────┐     │  ┌──────────────┐  │  ┌─────────────────────┐ │
│  │ Ray Data         │    │  │ Pandas        │  │  │ TFRecord/tf.data    │ │
│  │  • .read_parquet │    │  │  • validate   │  │  │  • .from_generator  │ │
│  │  • .read_csv     │    │  │ Polars       │  │  │  • .map/.batch      │ │
│  │  • .read_json    │    │  │  • .filter   │  │  │  • .shuffle/.cache  │ │
│  │  • Parallel I/O │    │  │ Great Expect. │  │  │  • .prefetch        │ │
│  │  • Lazy exec.   │    │  │  • expectations│  │  │                     │ │
│  └─────────────────┘    │  └──────────────┘  │  │ PyTorch DataLoader  │ │
│                          │                    │  │  • Dataset.__getitem__│ │
│  ┌─────────────────┐    │                    │  │  • num_workers        │ │
│  │ Apache Beam     │    │                    │  │  • pin_memory         │ │
│  │  • MapReduce    │    │                    │  │  • collate_fn         │ │
│  │  • Dataflow     │    │                    │  │  • prefetch_factor    │ │
│  │  • Flink/Spark  │    │                    │  │                       │ │
│  └─────────────────┘    │                    │  │ Ray Data              │ │
│                          │                    │  │  • .map_batches()     │ │
│                          │                    │  │  • .split_at_index()  │ │
│                          │                    │  │  • .repartition()     │ │
│                          │                    │  └─────────────────────┘ │
│                          │                                          │
│                          ▼                                           │
│                   ┌──────────────┐                                   │
│                   │   METADATA   │                                   │
│                   │   CATALOG    │                                   │
│                   │ • DataHub    │                                   │
│                   │ • Weights&Biases│                                │
│                   │ • MLflow     │                                   │
│                   │ • LakeFS     │                                   │
│                   └──────────────┘                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 PyTorch DataLoader

```python
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler

class CustomDataset(Dataset):
    def __init__(self, df, transform=None):
        self.df = df
        self.transform = transform

    def __len__(self):
        return len(self.df)

    def __getitem__(self, idx):
        row = self.df.iloc[idx]
        features = torch.tensor(row[feature_cols], dtype=torch.float32)
        label = torch.tensor(row['target'], dtype=torch.long)

        if self.transform:
            features = self.transform(features)

        return features, label

# Handle class imbalance via sampling
class_counts = np.bincount(y_train)
weights = 1.0 / class_counts[y_train]
sampler = WeightedRandomSampler(weights, num_samples=len(weights), replacement=True)

dataloader = DataLoader(
    dataset,
    batch_size=256,
    sampler=sampler,          # mutually exclusive with shuffle
    num_workers=4,            # parallel data loading
    pin_memory=True,          # faster GPU transfer
    prefetch_factor=2,        # prefetch batches
    drop_last=True,           # consistent batch sizes
    persistent_workers=True,  # avoid worker startup cost per epoch
)
```

### 5.2 TensorFlow tf.data

```python
import tensorflow as tf

def make_tf_dataset(file_pattern, batch_size=256, shuffle_buffer=10000, is_training=True):
    dataset = tf.data.Dataset.list_files(file_pattern, shuffle=is_training)
    dataset = dataset.interleave(
        lambda x: tf.data.TFRecordDataset(x, compression_type='GZIP'),
        cycle_length=tf.data.AUTOTUNE,
        num_parallel_calls=tf.data.AUTOTUNE,
    )
    dataset = dataset.map(parse_fn, num_parallel_calls=tf.data.AUTOTUNE)
    if is_training:
        dataset = dataset.shuffle(shuffle_buffer)
    dataset = dataset.batch(batch_size)
    dataset = dataset.prefetch(tf.data.AUTOTUNE)
    return dataset

train_ds = make_tf_dataset('data/train-*.tfrecord', is_training=True)
val_ds = make_tf_dataset('data/val-*.tfrecord', is_training=False)
```

### 5.3 Ray Data

```python
import ray.data

ds = ray.data.read_parquet("s3://bucket/data/")
    .repartition(200)                            # balance across workers
    .filter(lambda row: row['label'] >= 0)       # clean
    .map_batches(preprocess_fn, batch_size=4096)  # vectorized transform
    .split_at_indices([int(0.8 * len(ds)),       # train/val/test split
                       int(0.9 * len(ds))])
```

**Pipeline performance rules:**
- **Precompute what you can** (tokenization, normalization) and store preprocessed results. Disk is cheaper than GPU time.
- **Prefetch**: Always overlap data loading with model training. GPU should never wait for data.
- **Memory-map large files**: Use `numpy.memmap`, `zarr`, or `HDF5` for datasets that don't fit in RAM.
- **Cache aggressively**: `tf.data.Dataset.cache()`, `DataLoader(persistent_workers=True)`, Ray Data's internal object store.

---

## 6. Data Cataloging and Metadata Management

### 6.1 Why Catalog?

Without metadata, datasets are opaque blobs. A data catalog answers:

- **Provenance**: Where did this data come from? When was it collected?
- **Lineage**: Which transformations produced this version?
- **Quality**: What is the missing rate? Class distribution? Drift statistics?
- **Access**: Who can use this data? Are there PII constraints?

### 6.2 Metadata Schema

```python
dataset_metadata = {
    "dataset_id": "customer_churn_v3",
    "version": "3.2.1",
    "description": "Customer churn prediction dataset, cleaned and deduplicated",
    "source": {
        "system": "Salesforce CRM",
        "extract_date": "2025-01-15",
        "raw_location": "s3://data-raw/crm/2025-01-15/",
    },
    "schema": {
        "columns": [
            {"name": "age", "type": "int", "range": [18, 95], "null_rate": 0.02},
            {"name": "tenure_months", "type": "int", "range": [1, 72], "null_rate": 0.0},
            {"name": "contract_type", "type": "categorical", "levels": 3, "null_rate": 0.0},
            {"name": "monthly_charges", "type": "float", "range": [18.25, 118.75], "null_rate": 0.01},
        ],
        "target": "churn",
        "target_distribution": {"0": 0.735, "1": 0.265},
    },
    "transforms": [
        {"step": "deduplication", "rows_removed": 1523},
        {"step": "imputation", "method": "mice", "columns": ["monthly_charges"]},
        {"step": "encoding", "method": "target_encoding", "columns": ["contract_type"]},
        {"step": "scaling", "method": "robust", "columns": ["age", "monthly_charges"]},
    ],
    "splits": {
        "train": {"rows": 5600, "strategy": "stratified", "seed": 42},
        "val": {"rows": 1400, "strategy": "stratified", "seed": 42},
        "test": {"rows": 1000, "strategy": "stratified", "seed": 42, "held_out": True},
    },
    "drift_monitoring": {
        "baseline_psi": 0.0,
        "last_checked": "2025-03-01",
        "current_psi": 0.04,     # < 0.1 = OK, 0.1-0.25 = monitor, > 0.25 = action
    },
}
```

### 6.3 Tools Stack

| Tool | Purpose | Strength |
|------|---------|----------|
| **Great Expectations** | Data validation, profiling, documentation | Declarative expectations, data docs |
| **DVC** | Dataset versioning (git-like) | Reproducibility, S3/GCS backends |
| **LakeFS** | Data versioning at scale | Branch/merge semantics for data |
| **DataHub** | Metadata catalog, lineage | Searchable metadata graph |
| **Weights & Biases** | Artifact tracking + experiment logging | Tight ML workflow integration |
| **MLflow** | Experiment + artifact tracking | Model registry integration |

```python
# Great Expectations validation
import great_expectations as gx

context = gx.get_context()
datasource = context.sources.add_pandas("my_datasource")
asset = datasource.add_dataframe_asset(name="churn_data")
batch_request = asset.build_batch_request(dataframe=df)

validator = context.get_validator(batch_request=batch_request,
    create_expectation_suite_with_validator_name="churn_expectations")

validator.expect_table_row_count_to_be_between(min_value=5000, max_value=50000)
validator.expect_column_values_to_not_be_null("target")
validator.expect_column_values_to_be_between("age", min_value=18, max_value=95)
validator.save_expectation_suite()
```

---

## 7. Handling Imbalanced Datasets

### ASCII Art: Imbalanced Data Handling Workflow

```
                        ┌────────────────────────────────┐
                        │   IMBALANCED DATASET DETECTED   │
                        │   (class ratio > 5:1 or < 0.2) │
                        └──────────────┬─────────────────┘
                                       │
                              ┌────────▼────────┐
                              │  ANALYZE SEVERITY │
                              └────────┬─────────┘
                                       │
              ┌────────────────────────┼──────────────────────────┐
              │                         │                          │
     ┌────────▼────────┐      ┌────────▼────────┐       ┌─────────▼─────────┐
     │  MILD (5:1-10:1) │      │  MODERATE(10:1- │       │  SEVERE (>100:1)   │
     └────────┬────────┘      │  100:1)         │       └──────────┬────────┘
              │               └────────┬────────┘                  │
              │                        │                           │
     ┌────────▼────────┐      ┌────────▼────────┐       ┌──────────▼──────────┐
     │ Strategy 1:     │      │ Strategy 2:      │       │ Strategy 3:          │
     │ Class weights   │      │ Hybrid sampling  │       │ Anomaly detection    │
     │ in loss function│      │ + focal loss     │       │ or one-class         │
     │                 │      │                  │       │                      │
     │ wкласс = N /    │      │ ┌──────────────┐ │       │ Treat minority as    │
     │ (C * nласс)     │      │ │SMOTE minority │ │       │ anomalies           │
     │                 │      │ │to 1:2 ratio   │ │       │                      │
     │ PyTorch:        │      │ │then            │ │       │ Use: One-Class SVM,  │
     │ nn.CrossEntropy │      │ │Tomek-link clean│ │       │ Isolation Forest,    │
     │ (weight=weights)│      │ │majority near   │ │       │ Autoencoder          │
     └────────┬────────┘      │ │boundary        │ │       └──────────────────────┘
              │               └──────────────┘ │
              │                        │        │
              │               ┌────────▼────────┐│
              │               │ STRATEGY 2b:      ││
              │               │ Focal Loss       ││
              │               │                   ││
              │               │ FL(p) = -(1-p)^γ ││
              │               │            *log(p) ││
              │               │                   ││
              │               │ γ=2 → downweight  ││
              │               │ easy examples      ││
              │               │ focus on hard ones ││
              └───────────────┤                   ││
                              │ ┌───────────────┐ ││
                              │ │STRATEGY 2c:   │ ││
                              │ │Threshold tune │ ││
                              │ │               │ ││
                              │ │Move decision  │ ││
                              │ │boundary to    │ ││
                              │ │optimize F1    │ ││
                              │ │or PR-AUC      │ ││
                              │ └───────────────┘ ││
                              └───────────────────┘│
                                       │
                              ┌────────▼────────┐
                              │  ALWAYS DO:      │
                              │  • Stratified CV  │
                              │  • Monitor PR-AUC │
                              │  • Don't use      │
                              │    accuracy!       │
                              │  • Threshold tune │
                              │    on validation  │
                              └──────────────────┘
```

### Implementation Details

```python
import torch
import torch.nn as nn

# 1. Class weights in loss
class_counts = np.bincount(y_train)
class_weights = 1.0 / class_counts
class_weights = class_weights / class_weights.sum() * len(class_counts)
criterion = nn.CrossEntropyLoss(weight=torch.tensor(class_weights, dtype=torch.float32))

# 2. Focal Loss
class FocalLoss(nn.Module):
    def __init__(self, alpha=None, gamma=2.0, reduction='mean'):
        super().__init__()
        self.alpha = alpha    # class weights
        self.gamma = gamma    # focusing parameter
        self.reduction = reduction

    def forward(self, inputs, targets):
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = ((1 - pt) ** self.gamma) * ce_loss
        if self.alpha is not None:
            alpha_t = self.alpha[targets]
            focal_loss = alpha_t * focal_loss
        return focal_loss.mean() if self.reduction == 'mean' else focal_loss

# 3. Dynamic sampling — oversample rare classes per batch
def get_sampler_weights(labels):
    counts = np.bincount(labels)
    weights = 1.0 / counts[labels]
    return weights

sampler = WeightedRandomSampler(
    weights=get_sampler_weights(y_train),
    num_samples=len(y_train),
    replacement=True
)
```

**Evaluation metrics for imbalanced data (never use accuracy alone):**

| Metric | When to Use | Formula |
|--------|------------|---------|
| Precision@Recall | Search, information retrieval | Threshold at fixed recall |
| PR-AUC | General imbalanced | Area under precision-recall curve |
| F1 | Equal cost to FP and FN | `2*P*R/(P+R)` |
| F-beta | Asymmetric costs | `(1+β²)*P*R/(β²*P+R)` — β>1 favors recall |
| MCC | Balanced metric for binary | Correlation coefficient between prediction and truth |
| Cohen's kappa | Multi-class imbalanced | Agreement beyond chance |

---

## 8. Data Privacy

### ASCII Art: Privacy-Preserving Data Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 PRIVACY-PRESERVING DATA PIPELINE                            │
│                                                                             │
│  ┌───────────────┐     ┌────────────────────┐     ┌──────────────────────┐│
│  │  RAW DATA      │────▶│  ANONYMIZATION &    │────▶│  DIFFERENTIAL PRIVACY ││
│  │  (with PII)   │     │  PSEUDONYMIZATION   │     │  BUDGET TRACKER      ││
│  │               │     │                     │     │                      ││
│  │ • Name        │     │ ┌─────────────────┐ │     │ ┌──────────────────┐ ││
│  │ • Email       │     │ │ Direct Identifiers│ │     │ │ ε (epsilon)      │ ││
│  │ • SSN         │     │ │ • Hash/replace    │ │     │ │ δ (delta)        │ ││
│  │ • Address     │     │ │ • Tokenize        │ │     │ │                  │ ││
│  │ • Phone       │     │ │ • k-anonymize     │ │     │ │ Total budget:    │ ││
│  │               │     │ └─────────────────┘ │     │ │ ε_total = 1.0   │ ││
│  └───────────────┘     │ ┌─────────────────┐ │     │ │ Used: ε = 0.3   │ ││
│                         │ │ Quasi-Identifiers │ │     │ │ Remaining: 0.7  │ ││
│                         │ │ • Generalize DOB  │ │     │ │                  │ ││
│                         │ │   1992-03-15      │ │     │ │ Per query cost:  │ ││
│                         │ │   → 1992-03       │ │     │ │ ε = σ²/2Δ²      │ ││
│                         │ │ • Generalize ZIP  │ │     │ │ (Gaussian mech) │ ││
│                         │ │   94105            │ │     │ │                  │ ││
│                         │ │   → 94100          │ │     │ └──────────────────┘ ││
│                         │ │ • Suppress rare   │ │     │                      ││
│                         │ │   combinations    │ │     │ ┌──────────────────┐ ││
│                         │ └─────────────────┘ │     │ │ Noise injection  │ ││
│                         │ ┌─────────────────┐ │     │ │ • Laplacian(0,Δ/ε)│ ││
│                         │ │ Sensitive Attrs   │ │     │ │ • Gaussian(0,σ)  │ ││
│                         │ │ • Encrypt at rest │ │     │ │ Applied to:      │ ││
│                         │ │ • Access control  │ │     │ │ • Gradients      │ ││
│                         │ │ • Audit logging   │ │     │ │ • Aggregations  │ ││
│                         │ └─────────────────┘ │     │ │ • Model outputs  │ ││
│                         └────────────────────┘     │ └──────────────────┘ ││
│                                                      │                      ││
│                         ┌────────────────────┐     │ ┌──────────────────┐ ││
│                         │  FEDERATED LEARNING │     │ │  PRIVACY AUDIT   │ ││
│                         │  DATA PREP          │     │ │                  │ ││
│                         │                    │     │ │ • k-anonymity    │ ││
│                         │  Client 1:         │     │ │ • l-diversity    │ ││
│                         │  ┌──────────┐      │     │ │ • t-closeness    │ ││
│                         │  │Local data│─┐    │     │ │ • ε-budget track │ ││
│                         │  └──────────┘ │    │     │ │ • Membership     │ ││
│                         │               ▼    │     │ │   inference test │ ││
│                         │         ┌─────────┐│     │ └──────────────────┘ ││
│                         │         │ ∇f(x;θ) ││     └──────────────────────┘│
│                         │         │ + noise ││                              │
│                         │         └────┬────┘│                              │
│                         │              │     │                              │
│                         │  Client 2:   │     │    Server:                   │
│                         │  ┌──────────┐│     │    ┌──────────────────┐     │
│                         │  │Local data│┤│     │    │  Aggregate ∇     │     │
│                         │  └──────────┘│     │    │  ∇ = average(    │     │
│                         │               │     │    │    ∇₁, ∇₂, ...∇ₙ)│    │
│                         │               ▼     │    │  θ ← θ - η∇      │     │
│                         │         ┌─────────┐│     │                    │     │
│                         │         │ ∇f(x;θ) ││────▶│  Broadcast θ'     │     │
│                         │         │ + noise ││     │  to all clients   │     │
│                         │         └─────────┘│     └──────────────────┘     │
│                         └────────────────────┘                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.1 Differential Privacy

Differential privacy provides a mathematical guarantee: the inclusion or exclusion of any single individual's data changes the output distribution by at most a factor of e^ε.

```python
# Opacus (PyTorch) — per-sample gradient clipping + noise
from opacus import PrivacyEngine
from opacus.validators import ModuleValidator

model = ModuleValidator.fix(model)    # ensure batch norm → group norm
optimizer = torch.optim.SGD(model.parameters(), lr=0.01)

privacy_engine = PrivacyEngine()
model, optimizer, dataloader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=dataloader,
    epochs=10,
    target_epsilon=1.0,       # privacy budget
    target_delta=1e-5,        # probability of failure
    max_grad_norm=1.0,        # per-sample gradient clip norm
)

for epoch in range(10):
    for X_batch, y_batch in dataloader:
        optimizer.zero_grad()
        loss = criterion(model(X_batch), y_batch)
        loss.backward()
        optimizer.step()

    epsilon_spent = privacy_engine.get_epsilon(delta=1e-5)
    print(f"Epoch {epoch}: ε = {epsilon_spent:.2f}")
```

**Key parameters:**
- **ε (epsilon):** Privacy budget. Lower = more private. Common: ε ∈ [0.1, 10]. ε < 1 = strong privacy.
- **δ (delta):** Probability of catastrophic failure. Should be < 1/N (dataset size). Common: δ = 1e-5.
- **Clipping norm (C):** Bounds per-sample gradient contribution. Tune as hyperparameter.
- **Noise multiplier (σ):** Automatically determined from (ε, δ, C). More noise = more privacy, less accuracy.

### 8.2 k-Anonymity, l-Diversity, t-Closeness

```
  Original Data          k-Anonymized (k=2)      l-Diverse (l=2)
  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
  │ Name   │ DOB │ZIP│    │ Name   │ DOB │ZIP│    │ Name   │ DOB │ZIP│
  │ Alice   │1985│021│    │ ***    │1985│02* │    │ ***    │1985│02* │
  │ Bob     │1985│021│    │ ***    │1985│02* │    │ ***    │1985│02* │
  │ Charlie │1990│035│    │ ***    │199*│03* │    │ ***    │1990│03* │
  │ Diana   │1990│035│    │ ***    │199*│03* │    │ ***    │1990│03* │
  └─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                      │
                         At least k=2 rows           Each equivalence
                         share same QI values         class has ≥l=2
                         per quasi-identifier         distinct sensitive
                         group                        values (Disease: *)
                                                     
                         PROBLEM: If all in group      ENFORCES diversity
                         have same disease →           of sensitive attribute
                         no protection!                 within each group

  t-Closeness goes further: distribution of sensitive
  attribute in each group must be within distance t
  of the overall distribution (EMD distance ≤ t)
```

```python
# ARX anonymization framework (conceptual)
# pip install arx (Java-based, use via subprocess or py4j)

def check_k_anonymity(df, quasi_identifiers, k):
    groups = df.groupby(quasi_identifiers).size()
    violating_groups = groups[groups < k]
    if len(violating_groups) > 0:
        print(f"k-anonymity violated: {len(violating_groups)} groups < {k}")
    return len(violating_groups) == 0
```

### 8.3 Federated Learning Data Preparation

```python
# Simulate federated data partitioning
def partition_data_iid(dataset, num_clients):
    num_items = len(dataset) // num_clients
    client_data = []
    indices = np.random.permutation(len(dataset))
    for i in range(num_clients):
        client_indices = indices[i * num_items:(i + 1) * num_items]
        client_data.append(Subset(dataset, client_indices))
    return client_data

def partition_data_non_iid(dataset, num_clients, num_classes_per_client=2):
    """Non-IID: each client sees only a subset of classes (realistic)."""
    targets = np.array([dataset[i][1] for i in range(len(dataset))])
    class_indices = [np.where(targets == c)[0] for c in range(max(targets) + 1)]
    
    client_data = [[] for _ in range(num_clients)]
    for client_id in range(num_clients):
        assigned_classes = np.random.choice(
            len(class_indices), num_classes_per_client, replace=False
        )
        for c in assigned_classes:
            shard_size = len(class_indices[c]) // (num_clients // num_classes_per_client)
            start = (client_id % (len(class_indices[c]) // shard_size)) * shard_size
            client_data[client_id].extend(
                class_indices[c][start:start + shard_size]
            )
    return [Subset(dataset, idx) for idx in client_data]
```

### 8.4 Anonymization Checklist

| Technique | What It Protects | Residual Risk | Use When |
|-----------|------------------|---------------|----------|
| Pseudonymization | Direct identifiers | Linkage attack | Low-sensitivity data |
| Generalization | Quasi-identifiers | Homogeneity attack | k-anonymity compliance |
| Suppression | Rare combinations | Attribute disclosure | Combined with generalization |
| Noise addition | Aggregate statistics | Reconstruction | Statistical queries |
| Differential privacy | Individual privacy | Budget exhaustion | ML training, analytics |
| Synthetic data | Original data泄露 | Fidelity gap | Data sharing, testing |
| Encryption at rest | Unauthorized access | Key compromise | Regulatory compliance |

---

## Quick Reference: Decision Framework

```
        DATA ISSUE                           ACTION
        ─────────                            ────────
        Outliers detected          →  Robust methods or model-based detection
        Missing values (MCAR)      →  Mean/median or KNN imputation
        Missing values (MAR)        →  MICE / iterative imputation
        Missing values (MNAR)       →  Domain-specific + indicator columns
        Duplicates (exact)          →  Hash-based dedup
        Duplicates (fuzzy)          →  MinHash/LSH or embedding similarity
        High cardinality categoricals →  Target encoding or learned embeddings
        Severe class imbalance      →  SMOTE + focal loss + threshold tuning
        Temporal data               →  TimeSeriesSplit, no shuffle
        Grouped data                →  GroupKFold, no data leakage
        PII present                 →  k-anonymize + differential privacy
        Data too large for RAM      →  Memory-map, tf.data, or Ray Data

        VALIDATION RULE                      WHY
        ──────────────                       ────
        Fit scalers on train only            Prevents test leakage
        Stratify on minority class            Preserves class ratio
        No overlap between train/val groups   Prevents overoptimistic metrics
        Track ε budget across queries         Cumulative privacy loss
        Compute PR-AUC, not accuracy          Accuracy hides minority failure
        Version data with DVC                 Reproducibility
```

---

*This guide is part of the Agentic AI documentation series. For related topics, see the model training and evaluation guides.*

---

## Real References

### Data Cleaning, Outlier Detection, and Missing Data

1.  Liu, F.T., Ting, K.M., Zhou, Z.H., "Isolation Forest," *IEEE International Conference on Data Mining (ICDM)*, 2008. DOI: 10.1109/ICDM.2008.17

2.  Breunig, M.M., Kriegel, H.P., Ng, R.T., Sander, J., "LOF: Identifying Density-Based Local Outliers," *ACM SIGMOD International Conference on Management of Data*, 2000. DOI: 10.1145/342009.335388

3.  Schölkopf, B., Platt, J.C., Shawe-Taylor, J., Smola, A.J., Williamson, R.C., "Estimating the Support of a High-Dimensional Distribution," *Neural Computation*, 13(7):1443–1471, 2001. DOI: 10.1162/089976601750264965

4.  van Buuren, S., Groothuis-Oudshoorn, K., "mice: Multivariate Imputation by Chained Equations in R," *Journal of Statistical Software*, 45(3):1–67, 2011. DOI: 10.18637/jss.v045.i03

5.  Rubin, D.B., *Multiple Imputation for Nonresponse in Surveys*, Wiley, 1987. ISBN: 978-0-471-08705-4

6.  Chandrasekaran, R., Vishnawaths, S., "A Survey on Outlier Detection Methods for Data Streams," *International Journal of Computer Applications*, 2015.

### Data Transformation and Normalization

7.  Ioffe, S., Szegedy, C., "Batch Normalization: Accelerating Deep Network Training by Reducing Internal Covariate Shift," *ICML*, 2015. arXiv:1502.03167

8.  Wu, Y., He, K., "Group Normalization," *ECCV*, 2018. arXiv:1803.08494

9.  Yeo, I.K., Johnson, R.A., "A New Family of Power Transformations to Improve Normality or Symmetry," *Biometrika*, 87(4):954–959, 2000. DOI: 10.1093/biomet/87.4.954

10. Micci-Barreca, D., "A Preprocessing Scheme for High-Cardinality Categorical Attributes in Classification and Prediction Problems," *ACM SIGKDD Explorations Newsletter*, 3(1):27–32, 2001. DOI: 10.1145/507533.507538

### Train/Val/Test Splitting and Cross-Validation

11. Kohavi, R., "A Study of Cross-Validation and Bootstrap for Accuracy Estimation and Model Selection," *IJCAI*, 1995. DOI: 10.5555/1643031.1643049

12. Varma, S., Simon, R., "Bias in Error Estimation When Using Cross-Validation for Model Selection," *BMC Bioinformatics*, 7:91, 2006. DOI: 10.1186/1471-2105-7-91

13. Bengio, Y., Grandvalet, Y., "No Unbiased Estimator of the Variance of K-Fold Cross-Validation," *Journal of Machine Learning Research*, 5:1089–1105, 2004.

14. Absil, P.A.,iphery, and numerous others. See: Cawley, G.C., Talbot, N.L.C., "On Over-Fitting in Model Selection and Subsequent Selection Bias in Performance Evaluation," *Journal of Machine Learning Research*, 11:2079–2107, 2010.

15. Cerda, P., Varoquaux, G., Kégl, B., "Similarity Encoding for Learning Robust and Misspecified Categorical Encodings," *NeurIPS*, 2018. arXiv:1806.01099

### Data Augmentation

16. Zhang, H., Cisse, M., Dauphin, Y.N., Lopez-Paz, D., "mixup: Beyond Empirical Risk Minimization," *ICLR*, 2018. arXiv:1710.09412

17. DeVries, T., Taylor, G.W., "Improved Regularization of Convolutional Neural Networks with Cutout," *arXiv preprint*, 2017. arXiv:1708.04552

18. Yun, S., Han, D., Oh, S.J., Chun, S., Choe, J., Yoo, Y., "CutMix: Regularization Strategy to Train Strong Classifiers with Localizable Features," *ICCV*, 2019. arXiv:1905.04899

19. Shorten, C., Khoshgoftaar, T.M., "A Survey on Image Data Augmentation for Deep Learning," *Journal of Big Data*, 6:60, 2019. DOI: 10.1186/s40537-019-0197-0

20. Cubuk, E.D., Zoph, B., Mané, D., Vasudevan, V., Le, Q.V., "AutoAugment: Learning Augmentation Strategies from Data," *CVPR*, 2019. arXiv:1805.09501

21. Wei, J., Zou, K., "EDA: Easy Data Augmentation Techniques for Boosting Performance on Text Classification Tasks," *EMNLP-IJCNLP*, 2019. arXiv:1901.11196

22. Sennrich, R., Haddow, B., Birch, A., "Improving Neural Machine Translation Models with Monolingual Data," *ACL*, 2016. arXiv:1511.06709

23. Xie, Q., Dai, Z., Hovy, E., Luong, M.T., Le, Q.V., "Unsupervised Data Augmentation for Consistency Training," *NeurIPS*, 2020. arXiv:1904.12848

### Imbalanced Data

24. Chawla, N.V., Bowyer, K.W., Hall, L.O., Kegelmeyer, W.P., "SMOTE: Synthetic Minority Over-sampling Technique," *Journal of Artificial Intelligence Research (JAIR)*, 16:321–357, 2002. DOI: 10.1613/jair.953

25. Fernández, A., García, S., Herrera, F., Chawla, N.V., "SMOTE for Learning from Imbalanced Data: Progress and Challenges, Marking the 15-year Anniversary," *Journal of Artificial Intelligence Research*, 61:863–905, 2018. DOI: 10.1613/jair.1.11192

26. He, H., Bai, Y., Garcia, E.A., Li, S., "ADASYN: Adaptive Synthetic Sampling Approach for Imbalanced Learning," *IEEE International Joint Conference on Neural Networks (IJCNN)*, 2008. DOI: 10.1109/IJCNN.2008.4633969

27. Lin, T.Y., Goyal, P., Girshick, R., He, K., Dollár, P., "Focal Loss for Dense Object Detection," *ICCV*, 2017. arXiv:1708.02002

28. Cui, Y., Jia, M., Lin, T.Y., Song, Y., Belongie, S., "Class-Balanced Loss Based on Effective Number of Samples," *CVPR*, 2019. arXiv:1901.05555

29. Buda, M., Maki, A., Mazurowski, M.A., "A Systematic Study of the Class Imbalance Problem in Convolutional Neural Networks," *Neural Networks*, 106:249–259, 2018. DOI: 10.1016/j.neunet.2018.07.011

### Data Pipelines and Frameworks

30. PyTorch Documentation, "torch.utils.data — DataLoader, Dataset, Samplers," *PyTorch*, 2024. https://pytorch.org/docs/stable/data.html

31. TensorFlow Documentation, "tf.data: Build Efficient Input Pipelines," *TensorFlow*, 2024. https://www.tensorflow.org/guide/data

32. Isard, M., Budiu, M., Yu, Y., Birrell, A., Fetterly, D., "Dryad: Distributed Data-Parallel Programs from Sequential Building Blocks," *EuroSys*, 2007. DOI: 10.1145/1272996.1273005

33. Moritz, P., Nishihara, R., Wang, S., et al., "Ray: A Distributed Framework for Emerging AI Applications," *OSDI*, 2018. DOI: 10.5555/3291168.3291210

### Data Versioning and Cataloging

34. DVC Documentation, "Data Version Control," *DVC.org*, 2024. https://dvc.org/doc

35. Shah, A., Subramanian, S., "Great Expectations: Always Know What to Expect from Your Data," *Great Expectations Documentation*, 2024. https://docs.greatexpectations.io

36. Agarwal, A., Verma, S., "Data Versioning and Reproducibility in Machine Learning," *Proceedings of the VLDB Endowment*, 2020.

### Deduplication

37. Broder, A.Z., "On the Resemblance and Containment of Documents," *Compression and Complexity of Sequences (SEQS)*, IEEE, 1997. DOI: 10.1109/SEQUEN.1997.666900

38. Lee, K., Ippolito, D., Nystrom, A., Zhang, C., et al., "Deduplicating Training Data Makes Language Models Better," *ACL*, 2022. arXiv:2107.06499

39. Abbas, A., Tirumala, K., Jain, A., et al., "SemDeDup: Data Efficient Learning at Scale from Unneeded Data," *ICML*, 2023. arXiv:2303.09540

### Privacy and Differential Privacy

40. Abadi, M., Chu, A., Goodfellow, I., McMahan, H.B., Mironov, I., Talwar, K., Zhang, L., "Deep Learning with Differential Privacy," *ACM CCS*, 2016. arXiv:1607.00133

41. McMahan, H.B., Moore, E., Ramage, D., Hampson, S., y Arcas, B.A., "Communication-Efficient Learning of Deep Networks from Decentralized Data," *AISTATS*, 2017. arXiv:1602.05629

42. Dwork, C., Roth, A., "The Algorithmic Foundations of Differential Privacy," *Foundations and Trends in Theoretical Computer Science*, 9(3–4):211–407, 2014. DOI: 10.1561/0400000042

43. Sweeney, L., "k-Anonymity: A Model for Protecting Privacy," *International Journal on Uncertainty, Fuzziness and Knowledge-Based Systems*, 10(5):557–570, 2002. DOI: 10.1142/S0218488502001648

44. Machanavajjhala, A., Kifer, D., Gehrke, J., Venkitasubramaniam, M., "l-Diversity: Privacy Beyond k-Anonymity," *ICDE*, 2006. DOI: 10.1109/ICDE.2006.1

45. Li, N., Li, T., Venkatasubramanian, S., "t-Closeness: Privacy Beyond k-Anonymity and l-Diversity," *ICDE*, 2007. DOI: 10.1109/ICDE.2007.367856

46. Opacus Documentation, "Training PyTorch Models with Differential Privacy," *Opacus*, 2024. https://opacus.ai

### General Preprocessing and Feature Engineering

47. LeCun, Y., Bottou, L., Orr, G.B., Müller, K.R., "Efficient BackProp," in *Neural Networks: Tricks of the Trade*, Springer, 1998. DOI: 10.1007/978-3-642-35289-8_3

48. Pedregosa, F., Varoquaux, G., Gramfort, A., et al., "Scikit-learn: Machine Learning in Python," *Journal of Machine Learning Research*, 12:2825–2830, 2011.

49. Paszke, A., Gross, S., Massa, F., et al., "PyTorch: An Imperative Style, High-Performance Deep Learning Library," *NeurIPS*, 2019. DOI: 10.5555/3454287.3455008

50. Abadi, M., Agarwal, A., Barham, P., et al., "TensorFlow: Large-Scale Machine Learning on Heterogeneous Distributed Systems," *arXiv preprint*, 2016. arXiv:1603.04467
## References

- "Datasheets for Datasets," Gebru et al., NeurIPS 2021. https://arxiv.org/abs/1803.09010
- "Data Preprocessing for Deep Learning," various, TensorFlow Documentation. https://www.tensorflow.org/guide/data
- Hugging Face Transformers Documentation — Tokenization & Data Processing. https://huggingface.co/docs/transformers/
- "Scaling Data-Constrained Language Models," Muennighoff et al., 2023. https://arxiv.org/abs/2305.16264
- "The Pile: An 800GB Dataset," Gao et al., 2020. https://arxiv.org/abs/2101.00027
- "CC-Net: Extracting High Quality Monolingual Datasets," Wenzek et al., LREC 2020.
- "Deduplicating Training Data Makes Language Models Better," Lee et al., 2022. https://arxiv.org/abs/2107.06449
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
- Apache Arrow — Columnar in-memory analytics. https://arrow.apache.org/
- Pandas Documentation — Data manipulation. https://pandas.pydata.org/docs/
