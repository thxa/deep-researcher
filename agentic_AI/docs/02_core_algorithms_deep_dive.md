# Core Algorithms Deep Dive

## Algorithm Taxonomy Tree

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        MACHINE LEARNING ALGORITHMS                       │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
   ┌──────────────┐       ┌──────────────────┐       ┌────────────────┐
   │  CLASSICAL   │       │   DEEP LEARNING  │       │   ENSEMBLE     │
   │      ML      │       │                  │       │   METHODS      │
   └──────┬───────┘       └────────┬─────────┘       └───────┬────────┘
          │                        │                          │
    ┌─────┼──────┐          ┌──────┼──────┐            ┌─────┼─────┐
    ▼     ▼      ▼          ▼      ▼      ▼            ▼     ▼     ▼
 Linear  Tree-  Prob.    Feed-   Conv.  Recur.      Bagging Boost. Stack
 Models  Based  Based    Fwd.    Models  Models
    │     │      │        │       │      │            │       │      │
    ▼     ▼      ▼        ▼       ▼      ▼            ▼       ▼      ▼
 Lin.Reg DT   Naive    MLP     CNN    RNN          Random  XGBoost
 Log.Reg RF   Bayes    ┃       ┃     LSTM          Forest
 SVM     GBDT  ┃       ┃       ┃     GRU
 KNN          ┃       ┃       ┃      ┃
               ┃       ┃       ┃      ┃
               ▼       ▼       ▼      ▼
            Trans-  Diffusion  SSM/
            formers  Models    Mamba
              ┃
              ┃──── GANs
              ┃──── VAEs
```

---

## 1. Classical ML Algorithms

### 1.1 Linear Regression

**Internal Mechanics:**

Linear regression models the relationship between input features **x** ∈ ℝᵈ and a continuous target y:

$$\hat{y} = \mathbf{w}^T \mathbf{x} + b = \sum_{i=1}^{d} w_i x_i + b$$

**Loss Function (MSE):**

$$\mathcal{L}(\mathbf{w}, b) = \frac{1}{N} \sum_{i=1}^{N} (y_i - \hat{y}_i)^2 = \frac{1}{N} \sum_{i=1}^{N} \left(y_i - \mathbf{w}^T \mathbf{x}_i - b\right)^2$$

**Closed-Form Solution (OLS):**

$$\mathbf{w}^* = (\mathbf{X}^T \mathbf{X})^{-1} \mathbf{X}^T \mathbf{y}$$

**Gradient Descent Update:**

```
∂L/∂w_j = -(2/N) Σ x_ij (y_i - ŷ_i)
∂L/∂b   = -(2/N) Σ (y_i - ŷ_i)

w_j ← w_j - η · ∂L/∂w_j
b   ← b   - η · ∂L/∂b
```

**Regularization Variants:**
- **Ridge (L2):** minimize `L + λΣwᵢ²` — shrinks coefficients, never zero
- **Lasso (L1):** minimize `L + λΣ|wᵢ|` — induces sparsity, feature selection
- **Elastic Net:** minimize `L + λ₁Σ|wᵢ| + λ₂Σwᵢ²`

**Key Hyperparameters:**

| Hyperparameter | Range | Default | Effect |
|---|---|---|---|
| `fit_intercept` | bool | True | Whether to learn bias term |
| `alpha` (Ridge/Lasso) | [0, ∞) | 1.0 | Regularization strength |
| `l1_ratio` (ElasticNet) | [0, 1] | 0.5 | Mix of L1 vs L2 |
| `learning_rate` (SGD) | [1e-5, 1] | 0.01 | Step size for gradient descent |
| `max_iter` | [1, ∞) | 1000 | Maximum iterations |

**When to Use:** Continuous target, approximately linear relationship, interpretable baseline, high-dimensional sparse data (with L1).

---

### 1.2 Logistic Regression

**Internal Mechanics:**

Logistic regression models P(y=1|x) using the sigmoid function:

$$\hat{y} = \sigma(\mathbf{w}^T \mathbf{x} + b) = \frac{1}{1 + e^{-(\mathbf{w}^T \mathbf{x} + b)}}$$

**Forward Pass:**

```
z = w^T x + b          (logit / pre-activation)
ŷ = 1 / (1 + exp(-z))  (probability via sigmoid)
```

**Loss Function (Binary Cross-Entropy):**

$$\mathcal{L} = -\frac{1}{N}\sum_{i=1}^{N} \left[y_i \log(\hat{y}_i) + (1-y_i)\log(1-\hat{y}_i)\right]$$

**Gradient:**

$$\frac{\partial \mathcal{L}}{\partial w_j} = \frac{1}{N}\sum_{i=1}^{N} (\hat{y}_i - y_i) x_{ij}$$

**Multi-class Extension (Softmax):**

$$P(y=k|\mathbf{x}) = \frac{e^{\mathbf{w}_k^T \mathbf{x} + b_k}}{\sum_{j=1}^{K} e^{\mathbf{w}_j^T \mathbf{x} + b_j}}$$

**Key Hyperparameters:**

| Hyperparameter | Range | Default | Effect |
|---|---|---|---|
| `C` (inverse regularization) | [0, ∞) | 1.0 | Smaller = stronger regularization |
| `penalty` | l1, l2, elasticnet, none | l2 | Regularization type |
| `solver` | lbfgs, liblinear, saga | lbfgs | Optimization algorithm |
| `max_iter` | [1, ∞) | 100 | Convergence iterations |
| `class_weight` | dict or 'balanced' | None | Handle imbalanced classes |

**When to Use:** Binary/multi-class classification, probabilistic output needed, interpretable baseline, online learning, calibrating other models.

---

### 1.3 Decision Trees

**Internal Mechanics:**

A decision tree recursively partitions feature space via axis-aligned splits. At each node, the algorithm searches for the feature `j` and threshold `t` that maximizes information gain:

$$\text{Gain}(j, t) = I(\text{parent}) - \frac{N_{\text{left}}}{N} I(\text{left}) - \frac{N_{\text{right}}}{N} I(\text{right})$$

**Impurity Measures:**

```
Classification:
  Gini:    I_G = 1 - Σ_k p_k²
  Entropy: I_H = -Σ_k p_k log(p_k)

Regression:
  MSE:     I = (1/N) Σ (y_i - ȳ)²
  MAE:     I = (1/N) Σ |y_i - median(y)|
```

**Algorithm (CART):**

```
function BUILD_TREE(X, y, depth):
    if STOPPING_CRITERION(X, y, depth):
        return Leaf(prediction(X, y))

    best_gain = -∞
    for each feature j in features:
        for each threshold t in unique(X[:, j]):
            left  = indices where X[j] ≤ t
            right = indices where X[j] > t
            gain  = IMPURITY(y) - WEIGHTED_IMPURITY(y[left], y[right])
            if gain > best_gain:
                best_gain = gain; best_split = (j, t)

    left_subtree  = BUILD_TREE(X[left],  y[left],  depth+1)
    right_subtree = BUILD_TREE(X[right], y[right], depth+1)
    return Node(best_split, left_subtree, right_subtree)
```

```
        Decision Tree Structure
              ┌─────────┐
              │ x₃ ≤ 0.7?│
              └────┬──────┘
           ┌───────┴───────┐
      ┌────┴────┐     ┌────┴────┐
      │x₁ ≤ 2.1?│     │x₅ ≤ 0.3?│
      └────┬────┘     └────┬────┘
      ┌────┴────┐     ┌────┴────┐
   ┌──┴──┐  ┌──┴──┐ ┌──┴──┐ ┌──┴──┐
   │Class│  │Class│ │Class│ │Class│
   │  A  │  │  B  │ │  B  │ │  C  │
   └─────┘  └─────┘ └─────┘ └─────┘
```

**Key Hyperparameters:**

| Hyperparameter | Range | Default | Effect |
|---|---|---|---|
| `max_depth` | [1, ∞) | None | Maximum tree depth |
| `min_samples_split` | [2, ∞) | 2 | Min samples to split node |
| `min_samples_leaf` | [1, ∞) | 1 | Min samples at leaf |
| `max_features` | [1, d] | √d (clf), d (reg) | Features considered per split |
| `criterion` | gini, entropy, mse, mae | gini/mse | Split quality measure |
| `ccp_alpha` | [0, ∞) | 0.0 | Cost-complexity pruning |

**When to Use:** Interpretable models needed, mixed data types, non-linear relationships, as building blocks for ensembles.

---

### 1.4 Random Forests

**Internal Mechanics:**

Random Forest = Bagging + Feature Randomness. Train `B` independent decision trees on bootstrap samples, each considering only a random subset of `m` features at each split.

```
function RANDOM_FOREST_TRAIN(X, y, B, m):
    forests = []
    for b = 1 to B:
        X_b, y_b = BOOTSTRAP_SAMPLE(X, y)   # sample N with replacement
        tree_b  = BUILD_TREE(X_b, y_b, feature_subset_size=m)
        forests.append(tree_b)
    return forests

function RANDOM_FOREST_PREDICT(forests, x):
    Classification: ŷ = majority_vote({tree.predict(x) for tree in forests})
    Regression:     ŷ = mean({tree.predict(x) for tree in forests})
```

**Why It Works — Variance Reduction:**

$$\text{Var}(\bar{X}) = \rho\sigma^2 + \frac{1-\rho}{B}\sigma^2$$

Where ρ is the correlation between trees, σ² is individual tree variance, and B is the number of trees. Feature randomness reduces ρ, making the ensemble more effective.

**Out-of-Bag (OOB) Error Estimation:**

Each tree is trained on ~63.2% of data. The remaining ~36.8% (OOB samples) provide a free validation estimate without a held-out set.

```
   Random Forest Ensemble Architecture

   ┌──────────┐    ┌──────────┐    ┌──────────┐       ┌──────────┐
   │ Tree 1   │    │ Tree 2   │    │ Tree 3   │  ...  │ Tree B   │
   │ ┌──────┐ │    │ ┌──────┐ │    │ ┌──────┐ │       │ ┌──────┐ │
   │ │Boot- │ │    │ │Boot- │ │    │ │Boot- │ │       │ │Boot- │ │
   │ │strap │ │    │ │strap │ │    │ │strap │ │       │ │strap │ │
   │ │Sample│ │    │ │Sample│ │    │ │Sample│ │       │ │Sample│ │
   │ └──┬───┘ │    │ └──┬───┘ │    │ └──┬───┘ │       │ └──┬───┘ │
   │    │     │    │    │     │    │    │     │       │    │     │
   │ ┌──┴───┐ │    │ ┌──┴───┐ │    │ ┌──┴───┐ │       │ ┌──┴───┐ │
   │ │m ran-│ │    │ │m ran-│ │    │ │m ran-│ │       │ │m ran-│ │
   │ │dom   │ │    │ │dom   │ │    │ │dom   │ │       │ │dom   │ │
   │ │feat. │ │    │ │feat. │ │    │ │feat. │ │       │ │feat. │ │
   │ └──┬───┘ │    │ └──┬───┘ │    │ └──┬───┘ │       │ └──┬───┘ │
   │ ┌──┴───┐ │    │ ┌──┴───┐ │    │ ┌──┴───┐ │       │ ┌──┴───┐ │
   │ │Tree  │ │    │ │Tree  │ │    │ │Tree  │ │       │ │Tree  │ │
   │ │Learnt│ │    │ │Learnt│ │    │ │Learnt│ │       │ │Learnt│ │
   │ └──┬───┘ │    │ └──┬───┘ │    │ └──┬───┘ │       │ └──┬───┘ │
   │    │ŷ₁   │    │    │ŷ₂   │    │    │ŷ₃   │       │    │ŷ_B  │
   └────┼─────┘    └────┼─────┘    └────┼─────┘       └────┼─────┘
        │              │               │                    │
        └──────────────┴───────┬───────┴────────────────────┘
                                │
                      ┌─────────┴─────────┐
                      │  AGGREGATION      │
                      │  Majority Vote /  │
                      │  Mean             │
                      └─────────┬─────────┘
                                │
                             ŷ_final
```

**Key Hyperparameters:**

| Hyperparameter | Range | Default | Effect |
|---|---|---|---|
| `n_estimators` | [10, 1000+] | 100 | Number of trees |
| `max_depth` | [1, ∞) | None | Tree depth limit |
| `max_features` | [1, d] | √d (clf) | Features per split |
| `min_samples_leaf` | [1, ∞) | 1 | Min leaf size |
| `bootstrap` | bool | True | Use bootstrap sampling |
| `oob_score` | bool | False | Compute OOB error |
| `n_jobs` | [-1, ∞) | None | Parallel jobs (-1 = all) |

**When to Use:** Tabular data, robust out-of-the-box performance, feature importance needed, parallel training, low preprocessing needs.

---

### 1.5 Support Vector Machines (SVM)

**Internal Mechanics:**

SVM finds the maximum-margin hyperplane separating classes. The optimization problem:

$$\min_{\mathbf{w}, b} \frac{1}{2}\|\mathbf{w}\|^2 + C \sum_{i=1}^{N} \xi_i$$

Subject to: $y_i(\mathbf{w}^T \mathbf{x}_i + b) \geq 1 - \xi_i$, $\xi_i \geq 0$

**Kernel Trick (Dual Form):**

$$\hat{y}(\mathbf{x}) = \text{sign}\left(\sum_{i=1}^{N} \alpha_i y_i K(\mathbf{x}_i, \mathbf{x}) + b\right)$$

```
Kernel Functions:
  Linear:     K(x, x') = x^T x'
  Polynomial: K(x, x') = (γ x^T x' + r)^d
  RBF/Gauss:  K(x, x') = exp(-γ ||x - x'||²)
  Sigmoid:    K(x, x') = tanh(γ x^T x' + r)
```

```
     SVM Maximum Margin Hyperplane

          + (class 1)        • Support vectors
               ○  ○
          ○        ○    ○     ─── Decision boundary
     ────────────────────────── w^T x + b = 0
          ○     ○  ○
            ○  •     ○        ─── Margin boundaries
          ○      ○       ○       w^T x + b = ±1
     - (class 0)

     Margin = 2 / ||w||
     Only support vectors determine w
```

**Key Hyperparameters:**

| Hyperparameter | Range | Default | Effect |
|---|---|---|---|
| `C` | [0, ∞) | 1.0 | Regularization (↑ = less regularization) |
| `kernel` | linear, poly, rbf, sigmoid | rbf | Kernel function |
| `gamma` | [0, ∞) or 'scale' | scale | RBF kernel width (↑ = tighter) |
| `degree` | [1, ∞) | 3 | Polynomial degree |
| `coef0` | (-∞, ∞) | 0.0 | Independent term in poly/sigmoid |

**When to Use:** Small-to-medium datasets, high-dimensional spaces, non-linear boundaries (with kernels), text classification, image classification with engineered features.

---

### 1.6 K-Nearest Neighbors (KNN)

**Internal Mechanics:**

KNN is a lazy, non-parametric method. It stores all training data and predicts by majority vote (classification) or mean (regression) of the k nearest neighbors.

```
function KNN_PREDICT(x_new, X_train, y_train, k, distance):
    distances = [distance(x_new, x_i) for x_i in X_train]
    k_indices  = argsort(distances)[:k]
    k_labels   = y_train[k_indices]
    k_weights  = 1 / (distances[k_indices] + ε)  # for weighted voting

    Classification: return majority_vote(k_labels, k_weights)
    Regression:     return weighted_mean(k_labels, k_weights)

Distance Metrics:
  Euclidean:    d = √Σ(xᵢ - xᵢ')²
  Manhattan:     d = Σ|xᵢ - xᵢ'|
  Minkowski:     d = (Σ|xᵢ - xᵢ'|^p)^(1/p)
  Cosine:        d = 1 - (x·x')/(||x||·||x'||)
  Mahalanobis:   d = √((x-x')^T Σ^{-1} (x-x'))
```

**Bias-Variance Tradeoff with k:**
- Small k: low bias, high variance (sensitive to noise)
- Large k: high bias, low variance (over-smoothing)

**Key Hyperparameters:**

| Hyperparameter | Range | Default | Effect |
|---|---|---|---|
| `n_neighbors` | [1, N] | 5 | Number of neighbors |
| `weights` | uniform, distance | uniform | Weighting scheme |
| `metric` | euclidean, manhattan, etc. | minkowski | Distance metric |
| `p` | [1, ∞) | 2 | Minkowski power parameter |
| `algorithm` | auto, ball_tree, kd_tree, brute | auto | Search algorithm |

**When to Use:** Small datasets, low-dimensional data, quick prototyping, recommendation systems, anomalies requiring no training phase.

---

### 1.7 Naive Bayes

**Internal Mechanics:**

Naive Bayes applies Bayes' theorem with the *naive* assumption of feature independence:

$$P(y_k | \mathbf{x}) = \frac{P(\mathbf{x} | y_k) P(y_k)}{P(\mathbf{x})} = \frac{P(y_k) \prod_{j=1}^{d} P(x_j | y_k)}{P(\mathbf{x})}$$

**Prediction:**

$$\hat{y} = \arg\max_k P(y_k) \prod_{j=1}^{d} P(x_j | y_k)$$

(In practice, use log-sum to avoid underflow.)

**Variants:**

```
Gaussian NB (continuous features):
  P(x_j | y_k) = (1 / √(2πσ²_jk)) exp(-(x_j - μ_jk)² / (2σ²_jk))

Multinomial NB (count/frequency features):
  P(x_j | y_k) = (N_jk + α) / (N_k + α·|V|)    [with Laplace smoothing α]

Bernoulli NB (binary features):
  P(x_j | y_k) = P(x_j=1 | y_k)^x_j · (1 - P(x_j=1 | y_k))^(1 - x_j)
```

**Key Hyperparameters:**

| Hyperparameter | Range | Default | Effect |
|---|---|---|---|
| `var_smoothing` (Gaussian) | [1e-12, 1] | 1e-9 | Variance floor for stability |
| `alpha` (Multinomial/Bernoulli) | [0, ∞) | 1.0 | Laplace smoothing |
| `fit_prior` | bool | True | Learn class prior or use uniform |

**When to Use:** Text classification / spam filtering, multi-class with limited data, real-time prediction, when feature independence is approximately true, as a fast baseline.

---

### 1.8 XGBoost (Extreme Gradient Boosting)

**Internal Mechanics:**

XGBoost builds an ensemble of decision trees sequentially, where each new tree corrects the errors of previous trees using gradient boosting.

**Objective Function at Round t:**

$$\mathcal{L}^{(t)} = \sum_{i=1}^{N} l(y_i, \hat{y}_i^{(t-1)} + f_t(\mathbf{x}_i)) + \Omega(f_t)$$

**Second-Order Approximation (Taylor Expansion):**

$$\mathcal{L}^{(t)} \approx \sum_{i=1}^{N} \left[g_i f_t(\mathbf{x}_i) + \frac{1}{2} h_i f_t^2(\mathbf{x}_i)\right] + \Omega(f_t)$$

Where:
- $g_i = \partial_{\hat{y}^{(t-1)}} l(y_i, \hat{y}^{(t-1)})$ (first-order gradient)
- $h_i = \partial^2_{\hat{y}^{(t-1)}} l(y_i, \hat{y}^{(t-1)})$ (second-order gradient / Hessian)

**Optimal Leaf Value and Split Gain:**

$$w_j^* = -\frac{\sum_{i \in I_j} g_i}{\sum_{i \in I_j} h_i + \lambda}$$

$$\text{Gain} = \frac{1}{2} \left[\frac{(\sum_{i \in I_L} g_i)^2}{\sum_{i \in I_L} h_i + \lambda} + \frac{(\sum_{i \in I_R} g_i)^2}{\sum_{i \in I_R} h_i + \lambda} - \frac{(\sum_{i \in I} g_i)^2}{\sum_{i \in I} h_i + \lambda}\right] - \gamma$$

**Regularization:**

$$\Omega(f) = \gamma T + \frac{1}{2}\lambda \sum_{j=1}^{T} w_j^2$$

Where T = number of leaves, w_j = leaf weight.

```
   XGBoost Additive Training

   Round 1:            Round 2:            Round 3:
   ┌──────────┐        ┌──────────┐        ┌──────────┐
   │  Tree 1  │        │  Tree 2  │        │  Tree 3  │
   │ predicts │        │ corrects │        │ corrects │
   │  y_pred₁ │        │ residual₁│        │ residual₂│
   └────┬─────┘        └────┬─────┘        └────┬─────┘
        │                    │                    │
        ▼                    ▼                    ▼
   ŷ₁ = f₁(x)        ŷ₂ = f₁(x)+ηf₂(x)   ŷ₃ = f₁(x)+ηf₂(x)+ηf₃(x)
        │                    │                    │
        ▼                    ▼                    ▼
   residual₁ = y - ŷ₁  residual₂ = y - ŷ₂  final prediction ≈ y

   η = learning rate (shrinks each tree's contribution)
```

**Key Hyperparameters:**

| Hyperparameter | Range | Default | Effect |
|---|---|---|---|
| `n_estimators` | [1, 10000] | 100 | Number of boosting rounds |
| `learning_rate` (eta) | [0.001, 1] | 0.3 | Step size shrinkage |
| `max_depth` | [1, ∞) | 6 | Tree depth |
| `min_child_weight` | [0, ∞) | 1 | Min Hessian sum in leaf |
| `gamma` (min_split_loss) | [0, ∞) | 0 | Min loss reduction to split |
| `subsample` | (0, 1] | 1.0 | Row subsampling ratio |
| `colsample_bytree` | (0, 1] | 1.0 | Feature subsampling per tree |
| `reg_alpha` (L1) | [0, ∞) | 0 | L1 regularization on weights |
| `reg_lambda` (L2) | [0, ∞) | 1 | L2 regularization on weights |
| `scale_pos_weight` | (0, ∞) | 1 | Balance positive/negative weights |

**When to Use:** Tabular data competitions (Kaggle-dominant), structured/binary features, need for high accuracy with reasonable training time, feature importance analysis.

---

## 2. Deep Learning Architectures

### 2.1 Multi-Layer Perceptron (MLP)

**Internal Mechanics:**

A universal function approximator composed of fully-connected layers with non-linear activations.

$$\mathbf{h}^{(l)} = \sigma\left(\mathbf{W}^{(l)} \mathbf{h}^{(l-1)} + \mathbf{b}^{(l)}\right)$$

**Forward Pass:**

```
Input:  x ∈ ℝᵈ
Hidden: z⁽ˡ⁾ = W⁽ˡ⁾h⁽ˡ⁻¹⁾ + b⁽ˡ⁾     (pre-activation)
        h⁽ˡ⁾ = σ(z⁽ˡ⁾)                   (activation)
Output: ŷ   = W⁽ᴸ⁾h⁽ᴸ⁻¹⁾ + b⁽ᴸ⁾          (logits)
        ŷ   = softmax(ŷ) or sigmoid(ŷ)     (probability)
```

```
     MLP Architecture Diagram

     Input        Hidden 1        Hidden 2        Output
     Layer         (64)            (32)          Layer
     (d=4)

     ○ x₁ ──────●────────────●────────────●─────── ○ ŷ₁
                  │╲           │╲           │╲
     ○ x₂ ──────●────────────●────────────●─────── ○ ŷ₂
                  │╲           │╲           │╲
     ○ x₃ ──────●────────────●────────────
                  │╲           │╲
     ○ x₄ ──────●────────────●

         W⁽¹⁾∈ℝ⁶⁴ˣ⁴   W⁽²⁾∈ℝ³²ˣ⁶⁴   W⁽³⁾∈ℝ²ˣ³²

     Each connection: weight + bias
     Activation options per layer:
       σ(z) = ReLU(z) = max(0, z)          (most common)
       σ(z) = GELU(z) = z·Φ(z)             (transformers)
       σ(z) = Swish(z) = z·σ(z)             (modern)
       σ(z) = LeakyReLU(z) = max(αz, z)     (avoids dead neurons)
```

**Loss Functions:**
- Classification: Cross-Entropy Loss
- Regression: MSE / MAE / Huber Loss
- Multi-label: Binary Cross-Entropy per label

**Key Hyperparameters:**

| Hyperparameter | Range | Effect |
|---|---|---|
| Hidden layers & sizes | [1, ∞) per layer | Model capacity |
| Activation | ReLU, GELU, Swish, etc. | Non-linearity type |
| Learning rate | [1e-6, 1] | Step size |
| Batch size | [1, N] | Gradient estimate quality |
| Dropout rate | [0, 0.5] | Regularization |
| Weight init | He, Glorot, etc. | Training stability |

**When to Use:** Simple relationships, tabular data baseline, final classification head of larger architectures, low-data regimes with careful regularization.

---

### 2.2 Convolutional Neural Networks (CNN)

**Internal Mechanics:**

CNNs exploit spatial locality and translation invariance via shared-weight convolution filters.

**Convolution Operation:**

$$(\mathbf{X} * \mathbf{K})_{i,j} = \sum_{m}\sum_{n} \mathbf{X}_{i+m,\, j+n} \cdot \mathbf{K}_{m,n} + b$$

**Output Spatial Dimension:**

$$o = \left\lfloor \frac{i + 2p - k}{s} \right\rfloor + 1$$

Where i = input size, p = padding, k = kernel size, s = stride.

```
     CNN Architecture (VGG-style)

     Input              Conv Block 1           Conv Block 2           FC Layers
     224×224×3          224×224→112×112        112×112→56×56

     ┌──────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────┐
     │          │      │ Conv3-64      │      │ Conv3-128     │      │ FC-4096  │
     │  224×   ─┤  ├──▶│ ReLU         │──├──▶│ ReLU         │──├──▶│ ReLU     │──▶
     │  224×3   │      │ Conv3-64      │      │ Conv3-128     │      │ FC-4096  │
     │          │      │ ReLU         │      │ ReLU         │      │ ReLU     │
     └──────────┘      │ MaxPool/2    │      │ MaxPool/2    │      │ FC-1000  │
                       └──────────────┘      └──────────────┘      └──────────┘
                       64 filters            128 filters
                       3×3 kernels           3×3 kernels

     Key Operations in Each Conv Layer:
     ┌────────────────────────────────────────────────────────────────┐
     │                                                                │
     │   Input Volume         Conv Operation        Output Volume     │
     │   H×W×C_in             K×K×C_in×C_out        H'×W'×C_out      │
     │                                                                │
     │   ┌───────────┐        ┌─────┐                ┌───────────┐   │
     │   │ ╱╱╱╱╱╱╱ │        │ ╱╱╱ │  × C_out        │ ╱╱╱╱╱╱╱ │   │
     │   │ ╱╱╱╱╱╱╱ │   ⊛   │ ╱╱╱ │  ──────────▶    │ ╱╱╱╱╱╱╱ │   │
     │   │ ╱╱╱╱╱╱╱ │        │ ╱╱╱ │  (+bias)        │ ╱╱╱╱╱╱╱ │   │
     │   └───────────┘        └─────┘                └───────────┘   │
     │    224×224×3            3×3×3                   224×224×64    │
     │                         ↑                                      │
     │                    shared weights                              │
     │                    across spatial dims                         │
     └────────────────────────────────────────────────────────────────┘
```

**CNN Variants:**

```
Architecture Evolution:

 LeNet-5 (1998)        ResNet (2015)         EfficientNet (2019)
 ┌──────────┐          ┌──────────┐          ┌──────────┐
 │ Conv×2   │          │ Conv BN  │          │ MBConv   │
 │ FC×3     │          │ ReLU     │          │ SE block │
 │          │          │ ┌──────┐ │          │ Swish    │
 │ Simple   │          │ │skip  │ │          │ Compound │
 │ digits   │          │ │conn  │ │          │ scaling  │
 └──────────┘          │ └──────┘ │          │ (φ)      │
                       └──────────┘          └──────────┘

 Key Innovation:         Key Innovation:        Key Innovation:
 Local feature           Gradient flow via       Balanced width/
 extraction              residual shortcuts       depth/res scaling
```

**Loss Function:** Cross-Entropy (classification), MSE (regression)

**Key Hyperparameters:**

| Hyperparameter | Range | Effect |
|---|---|---|
| Number of filters | [8, 512+] | Feature capacity per layer |
| Kernel size | 1×1, 3×3, 5×5, 7×7 | Receptive field |
| Stride | [1, 4] | Spatial downsampling |
| Padding | same, valid | Output size preservation |
| Dilatation | [1, 4] | Receptive field expansion |
| Pool type | max, avg, strided conv | Downsampling method |

**When to Use:** Image classification/detection/segmentation, spatial data, video analysis, any grid-structured data, transfer learning from ImageNet.

---

### 2.3 RNN / LSTM / GRU

**Internal Mechanics:**

RNNs process sequential data by maintaining a hidden state updated at each timestep.

**Vanilla RNN:**

$$\mathbf{h}_t = \tanh(\mathbf{W}_{hh} \mathbf{h}_{t-1} + \mathbf{W}_{xh} \mathbf{x}_t + \mathbf{b}_h)$$

**Vanishing Gradient Problem:** After T steps, gradients scale as $\prod_{t=1}^{T} \mathbf{W}_{hh} \cdot \text{diag}(\sigma')$, which either explodes or vanishes.

**LSTM (Long Short-Term Memory):**

```
     LSTM Cell
     ┌─────────────────────────────────────────────────────────┐
     │                                                         │
     │  c_{t-1} ─────────────────●────────── x ───── c_t      │
     │              ↑             │          (1-f_t)·c_{t-1}    │
     │              │             │              + i_t·g_t      │
     │         ┌───┴───┐    ┌───┴───┐                          │
     │         │forget │    │  tanh │                          │
     │         │ gate  │    │  c̃_t  │                          │
     │         └───┬───┘    └───┬───┘                          │
     │             │             │                              │
     │          σ(Wf·[h,x]+bf)  tanh(Wc·[h,x]+bc)             │
     │             │             │                              │
     │         ┌───┴─────────────┴───┐                         │
     │         │  inputs from h,x    │                         │
     │         │                     │                         │
     │  h_{t-1}─┤──────────────────┌─┤──── h_t                │
     │         │    ┌───┐    ┌───┐ │                          │
     │         │    │out│    │ × │ │                          │
     │         │    │put│    │   │ │                          │
     │         │    │gat│    │   │ │                          │
     │         │    │e  │    │   │ │                          │
     │  x_t ───┤    └─┬─┘    └─┬─┘ │                          │
     │         │      │        │   │                          │
     │         └──────┼────────┘   │                          │
     │                │            │                          │
     │          σ(Wo·[h,x]+bo)    tanh(c_t)                  │
     │                                                         │
     │  h_t = o_t ⊙ tanh(c_t)                                 │
     │  c_t = f_t ⊙ c_{t-1} + i_t ⊙ c̃_t                    │
     │  f_t = σ(Wf·[h_{t-1}, x_t] + bf)   forget gate         │
     │  i_t = σ(Wi·[h_{t-1}, x_t] + bi)   input gate          │
     │  o_t = σ(Wo·[h_{t-1}, x_t] + bo)   output gate          │
     │  c̃_t = tanh(Wc·[h_{t-1}, x_t] + bc) candidate          │
     └─────────────────────────────────────────────────────────┘
```

**GRU (Gated Recurrent Unit) — Simplified LSTM:**

```
     GRU Cell
     ┌─────────────────────────────────┐
     │  h_t = (1 - z_t) ⊙ h_{t-1}    │
     │       + z_t ⊙ c̃_t              │
     │                                 │
     │  z_t = σ(Wz·[h_{t-1}, x_t])   │  update gate
     │  r_t = σ(Wr·[h_{t-1}, x_t])   │  reset gate
     │  c̃_t = tanh(W·[r_t⊙h_{t-1},x])│  candidate
     └─────────────────────────────────┘
     (merges forget+input gates → single update gate)
```

**Loss Function:** Cross-Entropy at each timestep (many-to-many) or at final timestep (many-to-one).

**Key Hyperparameters:**

| Hyperparameter | Range | Effect |
|---|---|---|
| Hidden size | [64, 2048] | Memory capacity |
| Num layers | [1, 8] | Depth of stacking |
| Dropout | [0, 0.5] | Between-layer regularization |
| Bidirectional | bool | Use future context |
| Gradient clipping | [0.1, 10] | Prevent exploding gradients |

**When to Use:** Time-series forecasting, language modeling (pre-Transformer era), sequential decision-making, speech recognition. Largely superseded by Transformers for NLP but still useful for small-data sequential tasks.

---

### 2.4 Transformers

**Internal Mechanics:**

The Transformer replaces recurrence with self-attention, enabling parallel computation and long-range dependency modeling.

**Scaled Dot-Product Attention:**

$$\text{Attention}(\mathbf{Q}, \mathbf{K}, \mathbf{V}) = \text{softmax}\left(\frac{\mathbf{Q}\mathbf{K}^T}{\sqrt{d_k}}\right)\mathbf{V}$$

**Multi-Head Attention:**

$$\text{MultiHead}(\mathbf{Q}, \mathbf{K}, \mathbf{V}) = \text{Concat}(\text{head}_1, ..., \text{head}_h)\mathbf{W}^O$$

where $\text{head}_i = \text{Attention}(\mathbf{Q}\mathbf{W}_i^Q, \mathbf{K}\mathbf{W}_i^K, \mathbf{V}\mathbf{W}_i^V)$

**Full Transformer Block:**

```
     Transformer Encoder Block                    Transformer Decoder Block

     ┌────────────────────────────┐              ┌────────────────────────────┐
     │                            │              │                            │
     │  x ──┬──▶ LayerNorm       │              │  x ──┬──▶ LayerNorm       │
     │      │     │               │              │      │     │               │
     │      │   Multi-Head        │              │      │ Masked Multi-Head   │
     │      │   Self-Attention    │              │      │ Self-Attention      │
     │      │     │               │              │      │     │               │
     │      │     ▼               │              │      │     ▼               │
     │      │     ⊕ ◀── x        │              │      │     ⊕ ◀── x        │
     │      │     │               │              │      │     │               │
     │      │   LayerNorm        │              │      │   LayerNorm        │
     │      │     │               │              │      │     │               │
     │      │   Feed-Forward     │              │      │ Cross-Attention     │
     │      │   Network          │              │      │ (Q from here,       │
     │      │   (FFN)            │              │      │  K,V from encoder)  │
     │      │     │               │              │      │     │               │
     │      │     ▼               │              │      │     ⊕ ◀────────     │
     │      │     ⊕ ◀────────     │              │      │     │               │
     │      │     │               │              │      │   LayerNorm        │
     │      │   LayerNorm        │              │      │     │               │
     │      │     │               │              │      │   Feed-Forward     │
     │      │     ▼               │              │      │     │               │
     │      └──▶ Output ────────▶│              │      │     ⊕ ◀────────     │
     │                            │              │      │     │               │
     └────────────────────────────┘              │      └──▶ Output ────────▶│
                                                 │                            │
                                                 └────────────────────────────┘
```

**Positional Encoding:**

$$PE_{(pos, 2i)} = \sin\left(\frac{pos}{10000^{2i/d_{\text{model}}}}\right), \quad PE_{(pos, 2i+1)} = \cos\left(\frac{pos}{10000^{2i/d_{\text{model}}}}\right)$$

**Feed-Forward Network:**

$$\text{FFN}(\mathbf{x}) = \text{ReLU}(\mathbf{x}\mathbf{W}_1 + \mathbf{b}_1)\mathbf{W}_2 + \mathbf{b}_2$$

Typically $d_{ff} = 4 \times d_{model}$.

**Loss:** Cross-Entropy for language modeling, task-specific otherwise.

**Key Hyperparameters:**

| Hyperparameter | Range | Typical | Effect |
|---|---|---|---|
| `d_model` | [128, 4096+] | 512-768 | Model dimension |
| `n_heads` | [1, d_model] | 8 | Parallel attention heads |
| `n_layers` | [1, 96+] | 6-12 | Depth |
| `d_ff` | [256, 16384] | 4×d_model | FFN hidden size |
| `dropout` | [0, 0.3] | 0.1 | Regularization |
| `max_seq_len` | [128, 200k+] | 512-2048 | Context window |

**When to Use:** NLP (dominant architecture), vision (ViT), speech, protein sequences, any task benefiting from global attention, large-scale pretraining + fine-tuning.

---

### 2.5 Diffusion Models

**Internal Mechanics:**

Diffusion models learn to reverse a gradual noising process. They define a forward process that adds Gaussian noise over T steps, then train a neural network to reverse each step.

**Forward Process (Noise Addition):**

$$q(\mathbf{x}_t | \mathbf{x}_{t-1}) = \mathcal{N}(\mathbf{x}_t; \sqrt{1-\beta_t}\,\mathbf{x}_{t-1}, \beta_t \mathbf{I})$$

**Closed-Form Marginal:**

$$q(\mathbf{x}_t | \mathbf{x}_0) = \mathcal{N}(\mathbf{x}_t; \sqrt{\bar\alpha_t}\,\mathbf{x}_0, (1-\bar\alpha_t)\mathbf{I})$$

Where $\bar\alpha_t = \prod_{s=1}^{t} \alpha_s$ and $\alpha_t = 1 - \beta_t$.

**Reverse Process (Denoising):**

$$p_\theta(\mathbf{x}_{t-1} | \mathbf{x}_t) = \mathcal{N}(\mathbf{x}_{t-1}; \boldsymbol{\mu}_\theta(\mathbf{x}_t, t), \sigma_t^2 \mathbf{I})$$

**Training Objective (Simplified):**

$$\mathcal{L}_\text{simple} = \mathbb{E}_{t, \mathbf{x}_0, \boldsymbol{\epsilon}} \left[\left\|\boldsymbol{\epsilon} - \boldsymbol{\epsilon}_\theta(\mathbf{x}_t, t)\right\|^2\right]$$

The model 𝜖_θ learns to predict the noise 𝜖 that was added.

**Sampling (DDPM):**

$$\mathbf{x}_{t-1} = \frac{1}{\sqrt{\alpha_t}} \left(\mathbf{x}_t - \frac{1-\alpha_t}{\sqrt{1-\bar\alpha_t}} \boldsymbol{\epsilon}_\theta(\mathbf{x}_t, t)\right) + \sigma_t \mathbf{z}$$

```
     Diffusion Model Forward and Reverse Process

     Forward (Adding Noise):
     x₀ ──▶ x₁ ──▶ x₂ ──▶ ... ──▶ x_T
     Clean  Noisy  Noisier        Pure Noise
      🖼️    ░░░    ▓▓▓            ████
             β₁     β₂              β_T
             └─ Each step adds Gaussian noise ─┘

     Reverse (Denoising):
     x_T ──▶ x_{T-1} ──▶ ... ──▶ x₁ ──▶ x₀
     Noise  Less Noise          Little    Clean
      ████    ▓▓▓               Noise     🖼️
             └─ Each step uses neural network ε_θ ─┘
                to predict and remove noise

     Training:
     ┌───────────────────────────────────────────────────┐
     │ 1. Sample x₀ ~ data distribution                  │
     │ 2. Sample t ~ Uniform(1, T)                       │
     │ 3. Sample ε ~ N(0, I)                             │
     │ 4. x_t = √(ᾱ_t) x₀ + √(1-ᾱ_t) ε               │
     │ 5. Minimize ||ε - ε_θ(x_t, t)||²                │
     └───────────────────────────────────────────────────┘

     Architecture: Typically U-Net with:
     - Time embedding (sinusoidal → MLP)
     - Skip connections between encoder/decoder
     - Self/cross-attention layers
     - ResNet blocks conditioned on timestep t
```

**Key Hyperparameters:**

| Hyperparameter | Range | Typical | Effect |
|---|---|---|---|
| `T` (diffusion steps) | [100, 4000] | 1000 | Trade quality vs speed |
| `β_schedule` | linear, cosine, sigmoid | cosine | Noise schedule |
| `β_start/end` | [1e-6, 0.02] | 1e-4 to 0.02 | Noise range |
| `model_channels` | [32, 256] | 128 | U-Net base channels |
| `num_res_blocks` | [1, 4] | 2 | ResNet blocks per level |
| `attention_resolutions` | varies | [32, 16] | Where to add attention |
| `ema_decay` | [0.99, 0.9999] | 0.9999 | EMA for sampling quality |

**When to Use:** Image/audio/video generation, molecular design, data augmentation, inpainting, super-resolution, any generative task where high fidelity matters.

---

### 2.6 Generative Adversarial Networks (GANs)

**Internal Mechanics:**

GANs frame generative modeling as a minimax game between a Generator G and Discriminator D.

**Objective Function:**

$$\min_G \max_D \; \mathcal{L}(G, D) = \mathbb{E}_{\mathbf{x} \sim p_{\text{data}}}[\log D(\mathbf{x})] + \mathbb{E}_{\mathbf{z} \sim p_z}[\log(1 - D(G(\mathbf{z})))]$$

**Optimal Discriminator:**

$$D^*(\mathbf{x}) = \frac{p_{\text{data}}(\mathbf{x})}{p_{\text{data}}(\mathbf{x}) + p_g(\mathbf{x})}$$

```
     GAN Architecture

     ┌──────────────┐                    ┌──────────────┐
     │   Latent      │    Fake data       │              │
     │   Space        │────────────────────│  Discriminator│
     │   z ~ N(0,I)  │                    │  D(x)        │
     │       │        │    Real data       │  "Real or     │
     │       ▼        │────────────────────│  Fake?"       │
     │   Generator    │                    │              │
     │   G(z)        │                    │  Output:      │
     │       │        │                    │  P(real|x)    │
     │       ▼        │                    │              │
     │   Fake data    │                    │  Loss:        │
     │   G(z) ≈ data │                    │  -E[log D(x)] │
     │               │                    │  -E[log(1-    │
     └──────────────┘                    │   D(G(z)))]   │
                                         └──────────────┘

     Training Loop:
     ┌───────────────────────────────────────────────────┐
     │ for each training iteration:                       │
     │                                                     │
     │   # Train Discriminator (k steps)                  │
     │   for k steps:                                     │
     │     real_data = sample(p_data)                     │
     │     z = sample(p_z)                                │
     │     fake_data = G(z)                                │
     │     L_D = -E[log D(real)] - E[log(1-D(fake))]     │
     │     update D parameters via gradient ascent         │
     │                                                     │
     │   # Train Generator                                │
     │   z = sample(p_z)                                  │
     │   L_G = -E[log D(G(z))]   # or max E[log(1-D(G))] │
     │   update G parameters via gradient descent          │
     └───────────────────────────────────────────────────┘

     Common GAN Variants:
     ┌────────────────┬───────────────────────────────────────┐
     │ DCGAN          │ Conv-based G and D with guidelines     │
     │ WGAN           │ Wasserstein distance + weight clipping│
     │ WGAN-GP        │ Wasserstein + gradient penalty         │
     │ StyleGAN       │ Style-based generator with mapping   │
     │ CycleGAN       │ Unpaired image-to-image translation   │
     │ Pix2Pix        │ Paired image-to-image translation    │
     │ SAGAN          │ Self-attention layers in G and D      │
     │ BigGAN         │ Large-scale + class-conditional      │
     │ ProGAN         │ Progressive growing of resolution    │
     └────────────────┴───────────────────────────────────────┘
```

**GAN Training Challenges:** Mode collapse, vanishing gradients, training instability, hyperparameter sensitivity.

**Key Hyperparameters:**

| Hyperparameter | Range | Effect |
|---|---|---|
| `latent_dim` | [8, 512] | Noise vector dimension |
| `lr_G / lr_D` | [1e-5, 1e-3] | Separate learning rates |
| `beta1` (Adam) | [0, 0.9] | Momentum (0.5 often better for GANs) |
| `n_critic` | [1, 10] | D updates per G update (WGAN) |
| `lambda_gp` | [0, 100] | Gradient penalty weight (WGAN-GP) |
| `gp_coef` | [0, 10] | Gradient penalty coefficient |

**When to Use:** Photorealistic image generation, image-to-image translation, data augmentation, super-resolution, style transfer. Use WGAN-GP for stable training.

---

### 2.7 Variational Autoencoders (VAEs)

**Internal Mechanics:**

VAEs learn a probabilistic latent space by jointly optimizing an encoder q_φ(z|x) and decoder p_θ(x|z).

**Evidence Lower Bound (ELBO):**

$$\log p(\mathbf{x}) \geq \mathbb{E}_{q_\phi(\mathbf{z}|\mathbf{x})}[\log p_\theta(\mathbf{x}|\mathbf{z})] - D_{\text{KL}}(q_\phi(\mathbf{z}|\mathbf{x}) \| p(\mathbf{z}))$$

**Loss Function:**

$$\mathcal{L} = \underbrace{\text{Reconstruction Loss}}_{\text{how well it reconstructs}} + \underbrace{\beta \cdot D_{\text{KL}}(q_\phi \| p)}_{\text{how close latent is to prior}}$$

**Reparameterization Trick (critical for backprop through sampling):**

$$\mathbf{z} = \boldsymbol{\mu}_\phi(\mathbf{x}) + \boldsymbol{\sigma}_\phi(\mathbf{x}) \odot \boldsymbol{\epsilon}, \quad \boldsymbol{\epsilon} \sim \mathcal{N}(0, \mathbf{I})$$

```
     VAE Architecture

     Encoder q_φ(z|x)                    Decoder p_θ(x|z)
     ┌───────────────────┐               ┌───────────────────┐
     │                    │               │                    │
     │  x ──────▶ MLP     │               │  z ──────▶ MLP     │
     │          │         │               │          │         │
     │     ┌────┴────┐   │               │     ┌────┴────┐   │
     │     │         │   │               │     │         │   │
     │     ▼         ▼   │    z ~ q(z|x) │     ▼         │   │
     │    μ_φ     log σ²_φ│  ◀─────────  │  x̂_θ ◀────┘   │
     │     │         │   │    Reparam.   │     │         │   │
     │     │    exp(0.5│   │    Trick:    │     ▼         │   │
     │     │     ·logσ²)│   │  z = μ + σε │  Reconstruct │   │
     │     │         │   │  where ε~N(0,I)│  x̂ ≈ x       │   │
     │     ▼         ▼   │               │                    │
     │     └────┬────┘   │               └───────────────────┘
     │          │         │
     │          ▼         │
     │     z = μ + σ ⊙ ε  │
     │          │         │
     └──────────┼─────────┘
                │
                ▼
          Latent Space z ∈ ℝ^d
          (well-structured, continuous)

     Loss = Reconstruction(x, x̂) + β · KL(q(z|x) || p(z))
            = BCE/MSE                = -0.5 Σ(1 + logσ² - μ² - σ²)
              (decoder quality)          (latent regularity)
```

**β-VAE:** Varying β trades off reconstruction quality vs latent disentanglement.

**Key Hyperparameters:**

| Hyperparameter | Range | Effect |
|---|---|---|
| `latent_dim` | [2, 512] | Latent space dimension |
| `β` (beta) | [0, 10+] | KL weight (1=standard, >1=disentangled) |
| Reconstruction loss | MSE, BCE | Output distribution assumption |
| Encoder/Decoder depth | [1, 10] | Network capacity |
| Free bits | [0, latent_dim] | Minimum KL per dimension |

**When to Use:** Latent space interpolation, disentangled representations, anomaly detection (low ELBO = anomaly), semi-supervised learning, controllable generation.

---

### 2.8 State Space Models (SSMs) / Mamba

**Internal Mechanics:**

SSMs model sequences via continuous-time linear differential equations, discretized for digital computation.

**Continuous-Time SSM:**

$$\frac{d\mathbf{x}(t)}{dt} = \mathbf{A}\mathbf{x}(t) + \mathbf{B}u(t), \quad y(t) = \mathbf{C}\mathbf{x}(t) + \mathbf{D}u(t)$$

**Discretization (Zero-Order Hold):**

$$\bar{\mathbf{A}} = e^{\Delta \mathbf{A}}, \quad \bar{\mathbf{B}} = (\Delta \mathbf{A})^{-1}(e^{\Delta \mathbf{A}} - \mathbf{I}) \cdot \mathbf{B}$$

**Recurrent Mode (Inference):**

$$\mathbf{x}_k = \bar{\mathbf{A}}\mathbf{x}_{k-1} + \bar{\mathbf{B}}u_k, \quad y_k = \mathbf{C}\mathbf{x}_k + \mathbf{D}u_k$$

**Convolutional Mode (Training — Parallel):**

$$\mathbf{y} = \bar{\mathbf{K}} * \mathbf{u}, \quad \text{where } \bar{\mathbf{K}} = (\mathbf{C}\bar{\mathbf{B}}, \mathbf{C}\bar{\mathbf{A}}\bar{\mathbf{B}}, \mathbf{C}\bar{\mathbf{A}}^2\bar{\mathbf{B}}, ...)$$

**Mamba Innovation — Selective Scan:**

```
     Standard SSM (time-invariant):           Mamba SSM (input-dependent):
     ┌─────────────────────────┐             ┌──────────────────────────────┐
     │ B, C, Δ are FIXED       │             │ B, C, Δ are FUNCTIONS of x  │
     │ (shared across tokens)   │             │ (different per token)         │
     │                           │             │                               │
     │ All tokens processed      │             │ Selective attention — tokens │
     │ identically               │             │ can choose to remember or    │
     │ Cannot filter content     │             │ forget based on input        │
     └─────────────────────────┘             └──────────────────────────────┘

     Mamba Block:
     ┌──────────────────────────────────────────────┐
     │  x ──▶ ┌─────────┐   ┌──────────────┐        │
     │        │ Linear   │──▶│  SiLU        │──┐    │
     │        │ proj d→2d│   │  activation  │  │    │
     │        └─────────┘   └──────────────┘  │    │
     │                                        │    │
     │  x ──▶ ┌─────────┐   ┌──────────────┐ │    │
     │        │ Linear   │──▶│  Selective   │ │    │
     │        │ proj d→E │   │  SSM Scan    │ │    │
     │        └─────────┘   │  (input-     │ │    │
     │                      │   dependent  │ │    │
     │                      │   B, C, Δ)   │ │    │
     │                      └──────────────┘ │    │
     │                              │         │    │
     │                              ▼         │    │
     │                       ┌──────────┐    │    │
     │                       │  Output  │    │    │
     │                       │  proj    │    │    │
     │                       │  E→d     │    │    │
     │                       └────┬─────┘    │    │
     │                            │          │    │
     │                       ┌────┴─────┐   │    │
     │                       │  × SiLU  │◄──┘    │
     │                       └────┬─────┘        │
     │                            │              │
     │                       ┌────┴─────┐        │
     │                       │  + x     │ (residual) │
     │                       └────┬─────┘        │
     │                            ▼              │
     │                          output            │
     └──────────────────────────────────────────────┘
```

**Mamba Complexity:**
- Training (parallel): O(N log N) via FFT-based convolution
- Inference (recurrent): O(1) per token (state size is fixed)
- Comparable to Transformer's O(N²) attention but linear in sequence length

**Key Hyperparameters:**

| Hyperparameter | Range | Typical | Effect |
|---|---|---|---|
| `d_model` | [128, 2048] | 768 | Model dimension |
| `d_state` (N) | [8, 64] | 16 | SSM state dimension |
| `d_conv` | [2, 5] | 3 | Local convolution kernel |
| `expand` (E) | [1, 4] | 2 | Inner dimension multiplier |
| `n_layers` | [1, 64+] | 24-64 | Model depth |

**When to Use:** Long-context modeling (>100k tokens), efficient inference (O(1) per token state), DNA/protein sequences, real-time audio processing, replacing Transformers when memory/O(n²) is a bottleneck.

---

## 3. Algorithm Comparison Table

```
┌──────────────────┬──────────────┬────────────┬──────────────┬──────────────┬──────────────┐
│ Algorithm        │ Problem Type │ Assumptions│ Training     │ Inference    │ Key          │
│                  │              │            │ Complexity   │ Complexity   │ Strength     │
├──────────────────┼──────────────┼────────────┼──────────────┼──────────────┼──────────────┤
│ Linear Reg.      │ Regression   │ Linearity  │ O(Nd)        │ O(d)         │ Interpretable│
│ Logistic Reg.    │ Classification│ Linear bnd │ O(Nd)        │ O(d)         │ Probabilistic│
│ Decision Tree    │ Both         │ Axis-align │ O(Nd log N)  │ O(depth)     │ Interpretable│
│ Random Forest    │ Both         │ Low corr.  │ O(BNd log N) │ O(B depth)   │ Robust       │
│ SVM              │ Both         │ Margin max │ O(N²~N³)     │ O(N_sv d)    │ High-dim     │
│ KNN              │ Both         │ None       │ O(1) lazy    │ O(Nd)        │ Simple       │
│ Naive Bayes      │ Classification│ Feature ind│ O(Nd)        │ O(dK)        │ Fast/text    │
│ XGBoost          │ Both         │ Additive   │ O(BNd log N) │ O(B depth)   │ Best tabular │
├──────────────────┼──────────────┼────────────┼──────────────┼──────────────┼──────────────┤
│ MLP              │ Both         │ None       │ O(NdHW)      │ O(dHW)       │ Flexible      │
│ CNN              │ Spatial data │ Locality   │ O(N·C·K²·HW) │ O(C·K²·HW)  │ Translation   │
│                  │              │            │              │              │ equivariance  │
│ RNN/LSTM/GRU     │ Sequential   │ Markov-like│ O(N·T·d²)    │ O(T·d²)     │ Sequential    │
│ Transformer      │ Both         │ None       │ O(N·T²·d)   │ O(T²·d)     │ Long-range    │
│                  │              │            │ +(N·T·d²)    │ +(T·d²)     │ dependencies  │
│ Diffusion        │ Generation   │ Gradual    │ O(N·T·HW)    │ O(T·HW)      │ High fidelity │
│                  │              │ noising    │              │ (slow)       │ generation    │
│ GAN              │ Generation   │ Adversarial│ O(N·d)       │ O(d)         │ Sharp outputs │
│ VAE              │ Generation   │ Gaussian   │ O(N·d)       │ O(d)         │ Latent space  │
│                  │              │            │              │              │ structure     │
│ SSM/Mamba        │ Sequential   │ Linear dyn │ O(N·T log T·d)│ O(T·d·N_state)│ Linear scaling│
│                  │              │            │              │ O(1) per tok │ efficient     │
└──────────────────┴──────────────┴────────────┴──────────────┴──────────────┴──────────────┘
```

---

## 4. Decision Flowchart: Choosing an Algorithm

```
                        ┌────────────────┐
                        │  START: What's │
                        │  your problem? │
                        └───────┬────────┘
                                │
                  ┌─────────────┼─────────────┐
                  ▼             ▼             ▼
           ┌──────────┐  ┌──────────┐  ┌──────────┐
           │Predicting│  │Predicting│  │Generating│
           │a number  │  │a category│  │new data  │
           │(Regress.)│  │(Classif.)│  │(Generat.)│
           └─────┬────┘  └─────┬────┘  └─────┬────┘
                 │             │              │
                 ▼             ▼              ▼
        ┌────────────┐  ┌────────────┐  ┌──────────────┐
        │How much    │  │How much    │  │What type of   │
        │data?       │  │data?       │  │data?           │
        │Linearity?  │  │Feature dim?│  │                │
        └──┬────┬────┘  └──┬────┬───┘  └──┬────┬───────┘
     Small│    │Large     Low│    │High   Image│   │Seq/Tab
           │    │           │    │            │    │
           ▼    ▼           ▼    ▼            ▼    ▼
      ┌────────┐ ┌───────┐┌──────┐┌────────┐┌──────────┐┌────────┐
      │Linear  │ │XGBoost││Naive ││SVM/    ││Diffusion ││Trans-  │
      │Reg.    │ │or     ││Bayes ││Random  ││or        ││former/ │
      │or      │ │Random ││or    ││Forest  ││GAN       ││Mamba   │
      │Ridge   │ │Forest ││LogReg││+       ││          ││        │
      │        │ │       ││      ││XGBoost ││          ││        │
      └────────┘ └───────┘└──────┘└────────┘└──────────┘└────────┘


     ┌─────────────────────────────────────────────────────────────┐
     │                  DETAILED DECISION GUIDE                     │
     │                                                             │
     │  1. Is your data TABULAR (spreadsheets, databases)?        │
     │     YES → Start with XGBoost/Random Forest                 │
     │            Small data? → Try Logistic/Linear Reg           │
     │            Need interpretability? → Decision Tree / Linear │
     │            Very high-dim sparse? → Linear/SVM (linear kern)│
     │                                                             │
     │  2. Is your data IMAGES?                                    │
     │     YES → CNN (ResNet, EfficientNet) for classification     │
     │            ViT for large datasets with pretraining           │
     │            Diffusion Models for generation                  │
     │            GAN for sharp, conditional generation             │
     │                                                             │
     │  3. Is your data SEQUENTIAL (text, time-series, DNA)?       │
     │     YES → Transformer for long-range, large data             │
     │            Mamba/SSM for very long sequences (>10k tokens)   │
     │            LSTM/GRU for small data or online settings        │
     │                                                             │
     │  4. Is your data AUDIO/SPEECH?                              │
     │     YES → CNN + RNN hybrid or Transformer (Whisper)         │
     │            Diffusion for audio generation                   │
     │                                                             │
     │  5. Do you need GENERATIVE capabilities?                    │
     │     YES → High-fidelity images → Diffusion Models           │
     │            Fast generation needed → GAN                     │
     │            Structured latent space → VAE                   │
     │            Text generation → Transformer (LLM)              │
     │                                                             │
     │  6. How much DATA do you have?                              │
     │     < 100 samples   → Simple models, heavy regularization   │
     │     100 - 10K       → Classical ML or small DL              │
     │     10K - 1M        → DL becomes viable                     │
     │     > 1M            → Large DL, pretraining, transfer       │
     │                                                             │
     │  7. INTERPRETABILITY needed?                                │
     │     Critical → Linear/Logistic Reg, Decision Tree            │
     │     Somewhat → Use SHAP/LIME on any model                   │
     │     Not needed → Black-box models are fine                  │
     └─────────────────────────────────────────────────────────────┘
```

---

## 5. Key Hyperparameter Summary by Algorithm

```
┌────────────────────┬────────────────────────────────────────────────────────────┐
│ Algorithm           │ Top 3 Hyperparameters to Tune First                      │
├────────────────────┼────────────────────────────────────────────────────────────┤
│ Linear Regression  │ 1. regularization strength (α/λ)  2. type (L1/L2/Elastic) │
│                    │ 3. learning rate (SGD)                                           │
│ Logistic Regression│ 1. C (inverse regularization)      2. penalty type         │
│                    │ 3. solver                                                           │
│ Decision Tree      │ 1. max_depth                        2. min_samples_split   │
│                    │ 3. ccp_alpha (pruning)                                             │
│ Random Forest      │ 1. n_estimators                     2. max_depth            │
│                    │ 3. max_features                                                    │
│ SVM                │ 1. C (regularization)               2. kernel type          │
│                    │ 3. gamma (RBF bandwidth)                                           │
│ KNN                │ 1. n_neighbors                      2. distance metric      │
│                    │ 3. weight function                                                  │
│ Naive Bayes        │ 1. alpha (smoothing)                2. distribution type    │
│                    │ 3. fit_prior                                                        │
│ XGBoost            │ 1. learning_rate + n_estimators     2. max_depth            │
│                    │ 3. min_child_weight + subsample                                      │
│ MLP                │ 1. hidden_sizes + activation        2. learning rate         │
│                    │ 3. dropout rate                                                     │
│ CNN                │ 1. number/type of conv layers       2. filter counts        │
│                    │ 3. kernel sizes + stride                                            │
│ LSTM/GRU           │ 1. hidden_size                      2. num_layers            │
│                    │ 3. dropout + gradient clip                                          │
│ Transformer        │ 1. d_model + n_heads                2. n_layers             │
│                    │ 3. learning rate + warmup steps                                      │
│ Diffusion Models   │ 1. T (diffusion steps)              2. noise schedule (β)   │
│                    │ 3. U-Net architecture                                               │
│ GAN                │ 1. lr_D + lr_G ratio                2. latent_dim            │
│                    │ 3. n_critic updates per G step                                       │
│ VAE                │ 1. latent_dim                       2. β (KL weight)        │
│                    │ 3. reconstruction loss type                                          │
│ SSM/Mamba          │ 1. d_model + expand (E)             2. d_state (N)           │
│                    │ 3. n_layers + d_conv                                                │
└────────────────────┴────────────────────────────────────────────────────────────┘
```

---

## 6. Training Considerations and Practical Tips

### 6.1 Weight Initialization

```
Initialization Strategy    | Use Case                    | Formula
───────────────────────────┼─────────────────────────────┼─────────────────────────
Xavier / Glorot           |sigmoid/tanh activation      │ W ~ N(0, 2/(fan_in + fan_out))
He / Kaiming              |ReLU and variants            │ W ~ N(0, 2/fan_in)
LeCun                     |SELU activation              │ W ~ N(0, 1/fan_in)
Orthogonal                |RNNs, deep networks          │ QR decomposition of random matrix
```

### 6.2 Learning Rate Schedules

```
Schedule        | Description                                  | When to Use
────────────────┼──────────────────────────────────────────────┼──────────────────────
Constant        | lr = lr₀                                      | Simple baselines
Step Decay      | lr = lr₀ × γ^(epoch/step_size)               | Standard CNN training
Cosine Annealing| lr = lr_min + 0.5(lr₀-lr_min)(1+cos(T_cur/T))│ Transformers, modern DL
Warmup + Decay  | Linear warmup then cosine/step decay          │ Transformers (must!)
Exponential     | lr = lr₀ × γ^epoch                           | Fine-tuning
1Cycle          | Single cycle up then down (Smith)              | Fast convergence
```

### 6.3 Regularization Techniques

```
Technique        | How It Works                        | Typical Dropout/Strength
─────────────────┼─────────────────────────────────────┼─────────────────────────
Dropout          | Randomly zero activations (p=0.1-0.5)│ p ∈ {0.1, 0.5}
L2 Regularization| Add λΣw² to loss                     │ λ ∈ {1e-5, 1e-2}
L1 Regularization| Add λΣ|w| to loss                    │ λ ∈ {1e-5, 1e-2}
Data Augmentation| Transform inputs (flip, crop, noise) │ Varies by domain
Early Stopping   | Stop when val loss increases         │ Patience: 5-20 epochs
Batch Norm       | Normalize activations per mini-batch  │ momentum=0.1, eps=1e-5
Layer Norm       | Normalize across features per sample  │ eps=1e-5
Label Smoothing  | Soften one-hot labels (ε=0.1)        │ ε = 0.1
Weight Decay     | L2 penalty via optimizer              │ wd ∈ {0, 0.01}
Stochastic Depth | Randomly skip layers during training  │ p ∈ {0.0, 0.5}
Mixup            | Linear interpolation of input pairs   │ α = 0.2-1.0
CutMix           | Cut and paste image regions           │ α = 1.0
```

### 6.4 Optimization Algorithms

```
Optimizer | Update Rule                                              | Best For
──────────┼───────────────────────────────────────────────────────────┼──────────────────
SGD       │ w ← w - lr · ∇L                                         │ +momentum for CNNs
SGD+Mom   │ v ← μv + ∇L;  w ← w - lr · v                           │ Classic, good gen.
Adam      │ m = β₁m+(1-β₁)g; v=β₂v+(1-β₂)g²; w←w-lr·m/(√v+ε)     │ Default most tasks
AdamW     │ Same as Adam + decoupled weight decay                    │ Transformers
AdaGrad   │ w ← w - lr · g / (√G + ε)                                │ Sparse features
RMSprop   │ v = αv + (1-α)g²; w ← w - lr·g/(√v+ε)                   │ RNNs
LAMB      │ Adam + layer-wise trust ratio                             │ Large-batch training
Lion      │ Sign-based update; memory-efficient (2 states not 2)    │ Memory-constrained
```

---

## 7. Common Loss Functions Reference

```
┌─────────────────────┬──────────────────────────────────────────────────┬──────────────────┐
│ Loss Function        │ Formula                                          │ Use Case         │
├─────────────────────┼──────────────────────────────────────────────────┼──────────────────┤
│ MSE (L2)            │ L = (1/N) Σ(yᵢ - ŷᵢ)²                          │ Regression        │
│ MAE (L1)            │ L = (1/N) Σ|yᵢ - ŷᵢ|                            │ Robust regression │
│ Huber                │ L = δ²/2 if |δ|≤δ else δ|δ|-δ²/2                 │ Robust regression │
│ Cross-Entropy        │ L = -Σ yᵢ log(ŷᵢ)                               │ Classification    │
│ Binary CE            │ L = -[y log ŷ + (1-y)log(1-ŷ)]                 │ Binary classif.   │
│ Focal Loss           │ L = -α(1-ŷ)^γ y log ŷ                           │ Imbalanced data   │
│ KL Divergence        │ KL(p||q) = Σ p log(p/q)                         │ VAE, distillation │
│ Hinge Loss           │ L = max(0, 1 - y·ŷ)                              │ SVM               │
│ Triplet Loss         │ L = max(0, d(a,p) - d(a,n) + margin)            │ Metric learning   │
│ Contrastive Loss     │ L = y·d² + (1-y)·max(0, margin-d)²              │ Siamese networks  │
│ Dice Loss            │ L = 1 - 2|P∩G|/(|P|+|G|)                        │ Segmentation      │
│ Wasserstein           │ L = max E[D(x_real)] - E[D(G(z))] + λ·GP      │ WGAN              │
└─────────────────────┴──────────────────────────────────────────────────┴──────────────────┘
```

---

## 8. Summary: From Theory to Practice

The choice of algorithm is a function of four key dimensions: **data type** (tabular, image, sequence, graph), **data quantity** (small, medium, large), **task** (classification, regression, generation, representation), and **constraints** (interpretability, latency, memory, accuracy).

- **Tabular data (most real-world ML):** XGBoost > Random Forest > simple NNs. Classical ML often wins here.
- **Images:** CNN for classification/detection, Diffusion/Transformer for generation, ViT for large-scale with pretraining.
- **Text/sequences:** Transformer is the default. Mamba/SSM for ultra-long sequences or O(1) inference. LSTM remains viable for small data or edge deployment.
- **Generation:** Diffusion for quality, GAN for speed and sharpness, VAE for structured latents and interpolation.
- **When in doubt:** Start simple (Linear/Logistic → Tree → Forest → XGBoost), then move to DL only when classical methods plateau or data type demands it.

---

## Real References

1. McCulloch, W. S., & Pitts, W., "A Logical Calculus of the Ideas Immanent in Nervous Activity", *Bulletin of Mathematical Biophysics*, 5(4):115–133, 1943. DOI: [10.1007/BF02478259](https://doi.org/10.1007/BF02478259)

2. Cortes, C., & Vapnik, V., "Support-Vector Networks", *Machine Learning*, 20(3):273–297, 1995. DOI: [10.1007/BF00994018](https://doi.org/10.1007/BF00994018)

3. Breiman, L., "Random Forests", *Machine Learning*, 45(1):5–32, 2001. DOI: [10.1023/A:1010933404324](https://doi.org/10.1023/A:1010933404324)

4. Chen, T., & Guestrin, C., "XGBoost: A Scalable Tree Boosting System", *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (KDD)*, pp. 785–794, 2016. arXiv: [1603.02754](https://arxiv.org/abs/1603.02754)

5. LeCun, Y., Bottou, L., Bengio, Y., & Haffner, P., "Gradient-Based Learning Applied to Document Recognition", *Proceedings of the IEEE*, 86(11):2278–2324, 1998. DOI: [10.1109/5.726791](https://doi.org/10.1109/5.726791)

6. He, K., Zhang, X., Ren, S., & Sun, J., "Deep Residual Learning for Image Recognition", *Proceedings of the IEEE Conference on Computer Vision and Pattern Recognition (CVPR)*, pp. 770–778, 2016. arXiv: [1512.03385](https://arxiv.org/abs/1512.03385)

7. Vaswani, A., Shazeer, N., Parmar, N., Uszkoreit, J., Jones, L., Gomez, A. N., Kaiser, Ł., & Polosukhin, I., "Attention Is All You Need", *Advances in Neural Information Processing Systems (NeurIPS)* 30, 2017. arXiv: [1706.03762](https://arxiv.org/abs/1706.03762)

8. Hochreiter, S., & Schmidhuber, J., "Long Short-Term Memory", *Neural Computation*, 9(8):1735–1780, 1997. DOI: [10.1162/neco.1997.9.8.1735](https://doi.org/10.1162/neco.1997.9.8.1735)

9. Goodfellow, I., Pouget-Abadie, J., Mirza, M., Xu, B., Warde-Farley, D., Ozair, S., Courville, A., & Bengio, Y., "Generative Adversarial Nets", *Advances in Neural Information Processing Systems (NeurIPS)* 27, 2014. arXiv: [1406.2661](https://arxiv.org/abs/1406.2661)

10. Ho, J., Jain, A., & Abbeel, P., "Denoising Diffusion Probabilistic Models", *Advances in Neural Information Processing Systems (NeurIPS)* 33, pp. 6840–6851, 2020. arXiv: [2006.11239](https://arxiv.org/abs/2006.11239)

11. Gu, A., & Dao, T., "Mamba: Linear-Time Sequence Modeling with Selective State Spaces", arXiv preprint arXiv:2312.00752, 2023. arXiv: [2312.00752](https://arxiv.org/abs/2312.00752)

12. Howard, A. G., Zhu, M., Chen, B., Kalenichenko, D., Wang, W., Weyand, T., Andreetto, M., & Adam, H., "MobileNets: Efficient Convolutional Neural Networks for Mobile Vision Applications", arXiv preprint arXiv:1704.04861, 2017. arXiv: [1704.04861](https://arxiv.org/abs/1704.04861)

13. Tan, M., & Le, Q. V., "EfficientNet: Rethinking Model Scaling for Convolutional Neural Networks", *Proceedings of the 36th International Conference on Machine Learning (ICML)*, pp. 6105–6114, 2019. arXiv: [1905.11946](https://arxiv.org/abs/1905.11946)

14. Goodfellow, I., Bengio, Y., & Courville, A., *Deep Learning*, MIT Press, 2016. ISBN: 978-0-2620-3561-3. URL: [https://www.deeplearningbook.org](https://www.deeplearningbook.org)

15. Fukushima, K., "Neocognitron: A Self-Organizing Neural Network Model for a Mechanism of Pattern Recognition Unaffected by Shift in Position", *Biological Cybernetics*, 36(4):193–202, 1980. DOI: [10.1007/BF00344251](https://doi.org/10.1007/BF00344251)

16. LeCun, Y., Boser, B., Denker, J. S., Henderson, D., Howard, R. E., Hubbard, W., & Jackel, L. D., "Backpropagation Applied to Handwritten Zip Code Recognition", *Neural Computation*, 1(4):541–551, 1989. DOI: [10.1162/neco.1989.1.4.541](https://doi.org/10.1162/neco.1989.1.4.541)

17. Krizhevsky, A., Sutskever, I., & Hinton, G. E., "ImageNet Classification with Deep Convolutional Neural Networks", *Advances in Neural Information Processing Systems (NeurIPS)* 25, pp. 1097–1105, 2012. DOI: [10.1145/3065386](https://doi.org/10.1145/3065386)

18. Simonyan, K., & Zisserman, A., "Very Deep Convolutional Networks for Large-Scale Image Recognition", *International Conference on Learning Representations (ICLR)*, 2015. arXiv: [1409.1556](https://arxiv.org/abs/1409.1556)

19. Szegedy, C., Liu, W., Jia, Y., Sermanet, P., Reed, S., Anguelov, D., Erhan, D., Vanhoucke, V., & Rabinovich, A., "Going Deeper with Convolutions", *Proceedings of the IEEE Conference on Computer Vision and Pattern Recognition (CVPR)*, pp. 1–9, 2015. arXiv: [1409.4842](https://arxiv.org/abs/1409.4842)

20. Cho, K., van Merriënboer, B., Gulcehre, C., Bahdanau, D., Bougares, F., Schwenk, H., & Bengio, Y., "Learning Phrase Representations using RNN Encoder-Decoder for Statistical Machine Translation", *Proceedings of the 2014 Conference on Empirical Methods in Natural Language Processing (EMNLP)*, pp. 1724–1734, 2014. arXiv: [1406.1078](https://arxiv.org/abs/1406.1078)

21. Kingma, D. P., & Welling, M., "Auto-Encoding Variational Bayes", *International Conference on Learning Representations (ICLR)*, 2014. arXiv: [1312.6114](https://arxiv.org/abs/1312.6114)

22. Rezende, D. J., Mohamed, S., & Wierstra, D., "Stochastic Backpropagation and Approximate Inference in Deep Generative Models", *Proceedings of the 31st International Conference on Machine Learning (ICML)*, pp. 1278–1286, 2014. arXiv: [1401.4082](https://arxiv.org/abs/1401.4082)

23. Arjovsky, M., Chintala, S., & Bottou, L., "Wasserstein Generative Adversarial Networks", *Proceedings of the 34th International Conference on Machine Learning (ICML)*, pp. 214–223, 2017. arXiv: [1701.07875](https://arxiv.org/abs/1701.07875)

24. Gulrajani, I., Ahmed, F., Arjovsky, M., Dumoulin, V., & Courville, A., "Improved Training of Wasserstein GANs", *Advances in Neural Information Processing Systems (NeurIPS)* 30, 2017. arXiv: [1704.00028](https://arxiv.org/abs/1704.00028)

25. Karras, T., Laine, S., & Aila, T., "A Style-Based Generator Architecture for Generative Adversarial Networks", *Proceedings of the IEEE/CVF Conference on Computer Vision and Pattern Recognition (CVPR)*, pp. 4401–4410, 2019. arXiv: [1812.04948](https://arxiv.org/abs/1812.04948)

26. Radford, A., Metz, L., & Chintala, S., "Unsupervised Representation Learning with Deep Convolutional Generative Adversarial Networks", *International Conference on Learning Representations (ICLR)*, 2016. arXiv: [1511.06434](https://arxiv.org/abs/1511.06434)

27. Sohl-Dickstein, J., Weiss, E., Maheswaranathan, N., & Ganguli, S., "Deep Unsupervised Learning Using Nonequilibrium Thermodynamics", *Proceedings of the 32nd International Conference on Machine Learning (ICML)*, pp. 2256–2264, 2015. arXiv: [1503.03585](https://arxiv.org/abs/1503.03585)

28. Song, Y., Sohl-Dickstein, J., Kingma, D. P., Kumar, A., Ermon, S., & Poole, B., "Score-Based Generative Modeling through Stochastic Differential Equations", *International Conference on Learning Representations (ICLR)*, 2021. arXiv: [2011.13456](https://arxiv.org/abs/2011.13456)

29. Gu, A., Goel, K., & Ré, C., "Efficiently Modeling Long Sequences with Structured State Spaces", *International Conference on Learning Representations (ICLR)*, 2022. arXiv: [2111.00396](https://arxiv.org/abs/2111.00396)

30. DeVries, T., & Taylor, G. W., "Improved Regularization of Convolutional Neural Networks with Cutout", arXiv preprint arXiv:1708.04552, 2017. arXiv: [1708.04552](https://arxiv.org/abs/1708.04552)

31. Zhang, H., Cisse, M., Dauphin, Y. N., & Lopez-Paz, D., "mixup: Beyond Empirical Risk Minimization", *International Conference on Learning Representations (ICLR)*, 2018. arXiv: [1710.09412](https://arxiv.org/abs/1710.09412)

32. Kingma, D. P., & Ba, J., "Adam: A Method for Stochastic Optimization", *International Conference on Learning Representations (ICLR)*, 2015. arXiv: [1412.6980](https://arxiv.org/abs/1412.6980)

33. Loshchilov, I., & Hutter, F., "Decoupled Weight Decay Regularization", *International Conference on Learning Representations (ICLR)*, 2019. arXiv: [1711.05101](https://arxiv.org/abs/1711.05101)

34. Ioffe, S., & Szegedy, C., "Batch Normalization: Accelerating Deep Network Training by Reducing Internal Covariate Shift", *Proceedings of the 32nd International Conference on Machine Learning (ICML)*, pp. 448–456, 2015. arXiv: [1502.03167](https://arxiv.org/abs/1502.03167)

35. Ba, L. J., Kiros, J. R., & Hinton, G. E., "Layer Normalization", arXiv preprint arXiv:1607.06450, 2016. arXiv: [1607.06450](https://arxiv.org/abs/1607.06450)

36. Srivastava, N., Hinton, G., Krizhevsky, A., Sutskever, I., & Salakhutdinov, R., "Dropout: A Simple Way to Prevent Neural Networks from Overfitting", *Journal of Machine Learning Research*, 15(1):1929–1958, 2014. URL: [https://jmlr.org/papers/v15/srivastava14a.html](https://jmlr.org/papers/v15/srivastava14a.html)

37. Glorot, X., & Bengio, Y., "Understanding the Difficulty of Training Deep Feedforward Neural Networks", *Proceedings of the 13th International Conference on Artificial Intelligence and Statistics (AISTATS)*, pp. 249–256, 2010.

38. He, K., Zhang, X., Ren, S., & Sun, J., "Delving Deep into Rectifiers: Surpassing Human-Level Performance on ImageNet Classification", *Proceedings of the IEEE International Conference on Computer Vision (ICCV)*, pp. 1026–1034, 2015. arXiv: [1502.01852](https://arxiv.org/abs/1502.01852)

39. Lin, T., Goyal, P., Girshick, R., He, K., & Dollar, P., "Focal Loss for Dense Object Detection", *Proceedings of the IEEE International Conference on Computer Vision (ICCV)*, pp. 2981–2988, 2017. arXiv: [1708.02002](https://arxiv.org/abs/1708.02002)

40. Friedman, J. H., "Greedy Function Approximation: A Gradient Boosting Machine", *Annals of Statistics*, 29(5):1189–1232, 2001. DOI: [10.1214/aos/1013203451](https://doi.org/10.1214/aos/1013203451)

41. Breiman, L., Friedman, J. H., Olshen, R. A., & Stone, C. J., *Classification and Regression Trees*, Wadsworth & Brooks/Cole, 1984. ISBN: 978-0-412-04841-8.

42. Cover, T., & Hart, P., "Nearest Neighbor Pattern Classification", *IEEE Transactions on Information Theory*, 13(1):21–27, 1967. DOI: [10.1109/TIT.1967.1053964](https://doi.org/10.1109/TIT.1967.1053964)

43. Hoerl, A. E., & Kennard, R. W., "Ridge Regression: Biased Estimation for Nonorthogonal Problems", *Technometrics*, 12(1):55–67, 1970. DOI: [10.1080/00401706.1970.10488634](https://doi.org/10.1080/00401706.1970.10488634)

44. Tibshirani, R., "Regression Shrinkage and Selection via the Lasso", *Journal of the Royal Statistical Society: Series B*, 58(1):267–288, 1996. DOI: [10.1111/j.2517-6161.1996.tb02080.x](https://doi.org/10.1111/j.2517-6161.1996.tb02080.x)

45. Zou, H., & Hastie, T., "Regularization and Variable Selection via the Elastic Net", *Journal of the Royal Statistical Society: Series B*, 67(2):301–320, 2005. DOI: [10.1111/j.1467-9868.2005.00503.x](https://doi.org/10.1111/j.1467-9868.2005.00503.x)

46. Nair, V., & Hinton, G. E., "Rectified Linear Units Improve Restricted Boltzmann Machines", *Proceedings of the 27th International Conference on Machine Learning (ICML)*, pp. 807–814, 2010.

47. Hendrycks, D., & Gimpel, K., "Gaussian Error Linear Units (GELUs)", arXiv preprint arXiv:1606.08415, 2016. arXiv: [1606.08415](https://arxiv.org/abs/1606.08415)

48. Ramachandran, P., Zoph, B., & Le, Q. V., "Swish: A Self-Gated Activation Function", arXiv preprint arXiv:1710.05941v1, 2017. arXiv: [1710.05941](https://arxiv.org/abs/1710.05941)

49. Huang, G., Liu, Z., Van Der Maaten, L., & Weinberger, K. Q., "Densely Connected Convolutional Networks", *Proceedings of the IEEE Conference on Computer Vision and Pattern Recognition (CVPR)*, pp. 4700–4708, 2017. arXiv: [1608.06993](https://arxiv.org/abs/1608.06993)

50. Dosovitskiy, A., Beyer, L., Kolesnikov, A., Weissenborn, D., Zhai, X., Unterthiner, T., Dehghani, M., Minderer, M., Heigold, G., Gelly, S., Uszkoreit, J., & Houlsby, N., "An Image Is Worth 16x16 Words: Transformers for Image Recognition at Scale", *International Conference on Learning Representations (ICLR)*, 2021. arXiv: [2010.11929](https://arxiv.org/abs/2010.11929)

51. Radford, A., Narasimhan, K., Salimans, T., & Sutskever, I., "Improving Language Understanding by Generative Pre-Training", OpenAI Technical Report, 2018. URL: [https://s3-us-west-2.amazonaws.com/openai-assets/research-covers/language-unsupervised/language_understanding_paper.pdf](https://s3-us-west-2.amazonaws.com/openai-assets/research-covers/language-unsupervised/language_understanding_paper.pdf)

52. Smith, L. N., "Cyclical Learning Rates for Training Neural Networks", *Proceedings of the IEEE Winter Conference on Applications of Computer Vision (WACV)*, pp. 464–472, 2017. arXiv: [1506.01186](https://arxiv.org/abs/1506.01186)

53. Loshchilov, I., & Hutter, F., "SGDR: Stochastic Gradient Descent with Warm Restarts", *International Conference on Learning Representations (ICLR)*, 2017. arXiv: [1608.03983](https://arxiv.org/abs/1608.03983)

54. Rumelhart, D. E., Hinton, G. E., & Williams, R. J., "Learning Representations by Back-Propagating Errors", *Nature*, 323(6088):533–536, 1986. DOI: [10.1038/323533a0](https://doi.org/10.1038/323533a0)

55. Bengio, Y., Simard, P., & Frasconi, P., "Learning Long-Term Dependencies with Gradient Descent is Difficult", *IEEE Transactions on Neural Networks*, 5(2):157–166, 1994. DOI: [10.1109/72.279181](https://doi.org/10.1109/72.279181)

56. Schmidhuber, J., "Multi-Column Deep Neural Networks for Image Classification", *Proceedings of the IEEE Conference on Computer Vision and Pattern Recognition (CVPR)*, pp. 3642–3649, 2012. arXiv: [1202.2745](https://arxiv.org/abs/1202.2745)

57. Higgins, I., Matthey, L., Pal, A., Burgess, C., Glorot, X., Botvinick, M., Mohamed, S., & Lerchner, A., "beta-VAE: Learning Basic Visual Concepts with a Constrained Variational Framework", *International Conference on Learning Representations (ICLR)*, 2017.

58. Ronneberger, O., Fischer, P., & Brox, T., "U-Net: Convolutional Networks for Biomedical Image Segmentation", *Medical Image Computing and Computer-Assisted Intervention (MICCAI)*, pp. 234–241, 2015. DOI: [10.1007/978-3-319-24574-4_28](https://doi.org/10.1007/978-3-319-24574-4_28)

59. Rombach, R., Blattmann, A., Lorenz, D., Esser, P., & Ommer, B., "High-Resolution Image Synthesis with Latent Diffusion Models", *Proceedings of the IEEE/CVF Conference on Computer Vision and Pattern Recognition (CVPR)*, pp. 10684–10695, 2022. arXiv: [2112.10752](https://arxiv.org/abs/2112.10752)

60. Zhu, J., Park, T., Isola, P., & Efros, A., "Unpaired Image-to-Image Translation Using Cycle-Consistent Adversarial Networks", *Proceedings of the IEEE International Conference on Computer Vision (ICCV)*, pp. 2242–2251, 2017. arXiv: [1703.10593](https://arxiv.org/abs/1703.10593)
## References

- Goodfellow, I., Bengio, Y., & Courville, A., "Deep Learning," MIT Press, 2016. https://www.deeplearningbook.org/
- Bishop, C.M., "Pattern Recognition and Machine Learning," Springer, 2006.
- Murph, K.P., "Machine Learning: A Probabilistic Perspective," MIT Press, 2012.
- Hastie, T., Tibshirani, R. & Friedman, J., "The Elements of Statistical Learning," 2nd Edition, Springer, 2009. https://hastie.su.domains/ElemStatLearn/
- Kingma, D.P. & Ba, J., "Adam: A Method for Stochastic Optimization," ICLR 2015. https://arxiv.org/abs/1412.6980
- Hochreiter, S. & Schmidhuber, J., "Long Short-Term Memory," NeurIPS 1997.
- He, K. et al., "Deep Residual Learning," CVPR 2016. https://arxiv.org/abs/1512.03385
- Vaswani, A. et al., "Attention Is All You Need," NeurIPS 2017. https://arxiv.org/abs/1706.03762
- Schulman, J. et al., "Proximal Policy Optimization Algorithms," 2017. https://arxiv.org/abs/1707.06347
- Snoek, J. et al., "Practical Bayesian Optimization of Machine Learning Algorithms," NeurIPS 2012.
