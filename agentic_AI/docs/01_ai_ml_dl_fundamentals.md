# AI, Machine Learning & Deep Learning: Fundamentals, Evolution & Taxonomy

> A comprehensive reference covering the history, mathematical foundations, key breakthroughs, and full landscape taxonomy of artificial intelligence — from the 1950s to 2025+.

---

## Table of Contents

1. [AI / ML / DL / GenAI Hierarchy](#1-ai--ml--dl--genai-hierarchy)
2. [History and Evolution of AI (1950s–2025+)](#2-history-and-evolution-of-ai-1950s2025)
3. [Types of Machine Learning](#3-types-of-machine-learning)
4. [Core Mathematical Foundations](#4-core-mathematical-foundations)
5. [Key Milestones and Breakthroughs](#5-key-milestones-and-breakthroughs)
6. [The Full AI Landscape Taxonomy](#6-the-full-ai-landscape-taxonomy)

---

## 1. AI / ML / DL / GenAI Hierarchy

The fields of Artificial Intelligence, Machine Learning, Deep Learning, and Generative AI form a nested hierarchy — each is a subset of the one above it. Understanding this containment relationship is the essential starting point.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ARTIFICIAL INTELLIGENCE (AI)                        │
│   The broad discipline of creating machines that exhibit intelligent        │
│   behavior — reasoning, learning, perception, language, decision-making.    │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                    MACHINE LEARNING (ML)                            │   │
│   │   Subset of AI: algorithms that improve through experience/data     │   │
│   │   without explicit programming. Covers statistical learning,        │   │
│   │   pattern recognition, generalization.                             │   │
│   │                                                                     │   │
│   │   ┌─────────────────────────────────────────────────────────────┐   │   │
│   │   │              DEEP LEARNING (DL)                              │   │   │
│   │   │   Subset of ML: multi-layered neural networks learning      │   │   │
│   │   │   hierarchical representations from raw data. Excels at      │   │   │
│   │   │   vision, speech, language, sequential decision-making.      │   │   │
│   │   │                                                             │   │   │
│   │   │   ┌─────────────────────────────────────────────────────┐   │   │   │
│   │   │   │          GENERATIVE AI (GenAI)                       │   │   │   │
│   │   │   │   Subset of DL: models that generate novel content  │   │   │   │
│   │   │   │   (text, images, audio, video, code, molecules...)  │   │   │   │
│   │   │   │   Learns data distributions, then samples from      │   │   │   │
│   │   │   │   them. Includes LLMs, diffusion models, VAEs, GANs │   │   │   │
│   │   │   └─────────────────────────────────────────────────────┘   │   │   │
│   │   └─────────────────────────────────────────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   AI also includes (outside ML):                                            │
│   • Expert systems, rule-based reasoning, knowledge graphs                  │
│   • Constraint satisfaction, planning, search algorithms                    │
│   • Logic programming (Prolog), ontologies, symbolic AI                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Relationships

| Concept | Contains | Core Mechanism | Example |
|---------|----------|----------------|---------|
| **AI** | ML + symbolic reasoning + planning | Any technique enabling intelligent behavior | A\* search, CyC, Siri |
| **ML** | DL + classical ML algorithms | Learning from data statistically | Random Forest, SVM |
| **DL** | GenAI + discriminative deep models | Multi-layer representation learning | CNNs, RNNs, Transformers |
| **GenAI** | LLMs, diffusion, VAEs, GANs, flow models | Learn distribution → generate samples | ChatGPT, DALL·E |

### The Spectrum: Symbolic ↔ Statistical ↔ Neural ↔ Generative

```
  Symbolic AI          Classical ML           Deep Learning         Generative AI
  (1950s–)             (1990s–)               (2012–)               (2020–)
  ──────────────────────────────────────────────────────────────────────────────►
  Rule-based        │  Statistical        │  Representation     │  Distribution
  Knowledge graphs  │  Feature engineering │  End-to-end learned │  Sampling &
  Logic & reasoning │  Hand-crafted feats  │  Automatic features │  conditional
  Expert systems    │  Small data regime   │  Big data regime    │  generation
                    │                      │                     │
  ◄─────── Good-old-fashioned AI (GOFAI) ──────►│◄──── Connectionist AI ────►
```

---

## 2. History and Evolution of AI (1950s–2025+)

### Detailed ASCII Timeline

```
  1950        1960        1970        1980        1990        2000        2010        2020
   │           │           │           │           │           │           │           │
   │  Turing   │           │           │  Back-     │           │  AlexNet   │           │
   │  Test     │  Percep-  │  1st AI   │  prop      │  SVMs     │  Word2Vec  │  GPT-3    │
   │  (1950)   │  tron     │  Winter   │  revived   │  Boosting │  DeepRL    │  DALL·E   │
   │           │  (1958)   │  (1974)   │  (1986)    │  (90s)    │  (2012-15) │  (2020-21)│
   │  Dart-    │           │           │  CNNs      │  Deep     │  Attn/TF   │           │
   │  mouth    │  ELIZA    │  Frames   │  (LeCun)   │  Blue     │  (2017)     │  ChatGPT  │
   │  (1956)   │  (1966)   │  (1975)   │  (1989)    │  (1997)   │  BERT/GPT  │  (2022)   │
   │           │           │           │           │           │  (2018-19) │           │
   ▼           ▼           ▼           ▼           ▼           ▼           ▼           ▼
  ──┬───────────┬───────────┬───────────┬───────────┬───────────┬───────────┬───────────┬──
    │  FOUNDING │  OPTIMISM │  WINTER & │  NEURAL   │  CLASSICAL│  DEEP     │  TRANS-   │
    │  ERA      │  & EARLY  │  EXPERT   │  RENAISS- │  ML       │  LEARNING │  FORMERS  │
    │           │  TOOLS    │  SYSTEMS  │  ANCE     │  GOLDEN  │  REVOLUTN │  & GenAI  │
    │           │           │           │           │  AGE      │           │  ERA      │
  ──┴───────────┴───────────┴───────────┴───────────┴───────────┴───────────┴───────────┴──
```

### Era-by-Era Breakdown

#### 1950s — The Founding Era

- **1950**: Alan Turing publishes *Computing Machinery and Intelligence*, proposing the Turing Test as the operational definition of machine intelligence.
- **1956**: Dartmouth Conference — John McCarthy coins the term "Artificial Intelligence." Attendees include Minsky, Newell, Simon, and others who would define the field for decades.
- **1958**: Frank Rosenblatt introduces the **Perceptron**, the first computational model of a neuron capable of learning linearly separable patterns.

#### 1960s — Optimism & Early Tools

- **1966**: Joseph Weizenbaum creates **ELIZA**, an early natural language processing program simulating a Rogerian psychotherapist — demonstrating the illusion of understanding.
- **1969**: Marvin Minsky and Seymour Papert publish *Perceptrons*, proving that single-layer perceptrons cannot learn the XOR function. While the book is mathematically correct, its effect is devastating: funding for neural network research collapses, beginning the first AI Winter.

#### 1970s — AI Winter & Expert Systems

- **1974–1980 (First AI Winter)**: The Lighthill Report (UK, 1973) and DARPA funding cuts gut AI research. General-purpose AI is seen as infeasible; focus shifts to narrow, rule-based **expert systems**.
- **1975**: Marvin Minsky introduces the **frame** knowledge representation, a precursor to modern knowledge graphs and structured reasoning.

#### 1980s — Neural Renaissance

- **1986**: Rumelhart, Hinton, and Williams publish the landmark paper popularizing **backpropagation** for training multi-layer neural networks, resolving Minsky's XOR critique and reopening the neural network research avenue.
- **1989**: Yann LeCun applies **backpropagation to convolutional architectures** for handwritten digit recognition (LeNet), demonstrating that deep neural networks can learn visual features end-to-end.

#### 1990s — Classical ML Golden Age

- **1995**: **Support Vector Machines** (Cortes & Vapnik) become the dominant classification paradigm, offering strong theoretical guarantees and excellent performance on small-to-medium datasets.
- **Mid-90s**: Ensemble methods — **Boosting** (Freund & Schapire, 1997), **Random Forests** (Breiman, 2001) — become staples of applied ML.
- **1997**: IBM **Deep Blue** defeats Garry Kasparov at chess using exhaustive search and evaluation functions — a milestone for symbolic/brute-force AI, not learning.

#### 2000s — Data & Compute Convergence

- The web enables unprecedented data collection. Moore's Law delivers the GPU compute needed for neural networks. The stage is set for deep learning.

#### 2010s — Deep Learning Revolution

- **2012**: **AlexNet** (Krizhevsky, Sutskever, Hinton) wins ImageNet with a massive performance gap (top-5 error: 15.3% vs. 26.2% for runner-up). This is the tipping point — the proof that deep, GPU-trained CNNs dominate computer vision.
- **2013–14**: **Word2Vec** (Mikolov) and **GloVe** (Pennington et al.) demonstrate that distributed word representations capture semantic relationships, laying the groundwork for modern NLP.
- **2014**: **GANs** (Generative Adversarial Networks, Goodfellow et al.) introduce a training paradigm where two networks compete, enabling photorealistic image generation.
- **2014**: **Seq2Seq** (Sutskever et al.) shows encoder-decoder architectures can learn to translate languages end-to-end.
- **2015**: **Deep Reinforcement Learning** — DQN (Mnih et al.) masters Atari games from pixels; **AlphaGo** (Silver et al.) defeats Fan Hui, later Lee Sedol (2016).
- **2017**: **Attention Is All You Need** (Vaswani et al.) — the Transformer architecture eliminates recurrence entirely, enabling massive parallelism and scaling.
- **2018**: **BERT** (Devlin et al.) and **GPT-1** (Radford et al.) introduce the pretrain-then-finetune paradigm for language models. Transfer learning arrives in NLP.

#### 2020s — Transformer Scaling & Generative AI Era

- **2020**: **GPT-3** (Brown et al., 175B parameters) demonstrates few-shot in-context learning — the model performs tasks with only a prompt, no gradient updates required.
- **2021**: **DALL·E** (OpenAI), **Codex** (OpenAI) — multimodal generation, code synthesis from natural language.
- **2022**: **Stable Diffusion** democratizes image generation. **ChatGPT** (Nov 2022) brings conversational AI to hundreds of millions of users, catalyzing mainstream AI adoption.
- **2023**: **GPT-4** — multimodal reasoning over text and images. **Mistral 7B**, **Llama 2** ignite open-source LLM ecosystem. **RLHF** (Reinforcement Learning from Human Feedback) becomes standard alignment technique.
- **2024**: **Mixture-of-Experts** architectures (Mixtral, GPT-4 rumored). **Long-context windows** (128K+ tokens). **Agentic AI** — LLMs orchestrating tool use, planning, and multi-step reasoning. **Video generation** (Sora, Veo). **Reasoning models** (o1, o3, DeepSeek-R1) demonstrate chain-of-thought at inference time.
- **2025+**: Agentic workflows, tool-augmented LLMs, neuromorphic hardware, continued scaling with efficiency gains, constitutional AI, mechanistic interpretability, and the push toward more general systems.

---

## 3. Types of Machine Learning

### Comparison Chart

```
┌──────────────────┬──────────────────────┬──────────────────────┬──────────────────────┬──────────────────────┐
│   Attribute      │     SUPERVISED        │    UNSUPERVISED       │   REINFORCEMENT      │   SELF-SUPERVISED    │
├──────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ DATA             │ Labeled (x → y)       │ Unlabeled (x only)   │ Reward signal only   │ Unlabeled; labels     │
│                  │                       │                      │ (state, action, r)   │ derived from input   │
├──────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ GOAL             │ Predict y from x      │ Discover structure   │ Maximize cumulative  │ Learn representations │
│                  │                       │ in data              │ reward               │ via pretext tasks    │
├──────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ FEEDBACK         │ Direct (ground truth) │ None (intrinsic      │ Delayed, sparse      │ Implicit (predict     │
│                  │                       │ structure)           │                      │ masked/next token)   │
├──────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ KEY ALGORITHMS   │ Linear/Logistic Regr. │ K-Means, DBSCAN,     │ Q-Learning, DQN,     │ BERT (MLM), GPT      │
│                  │ SVM, Decision Trees,  │ PCA, t-SNE, UMAP,   │ PPO, SAC, A3C,       │ (next-token), MoCo,  │
│                  │ Random Forest, XGBoost│ GMM, Autoencoders   │ AlphaGo, TD3        │ SimCLR, MAE          │
├──────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ TYPICAL TASKS    │ Classification,       │ Clustering,          │ Game playing,        │ Language modeling,   │
│                  │ Regression,           │ Dim. reduction,      │ Robotics control,    │ representation      │
│                  │ Object detection      │ Anomaly detection    │ Resource allocation │ learning, pretraining│
├──────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ SCALABILITY      │ Limited by labeling  │ Scales with data     │ Limited by reward    │ Scales with compute │
│                  │ cost & quality        │                      │ sparsity & sim cost  │ and data (no labels)│
├──────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ EXAMPLE IN DL    │ ImageNet CNN,        │ Deep clustering,     │ AlphaGo, ChatGPT     │ GPT pretraining,    │
│                  │ Medical diagnosis,   │ Anomaly autoencoder  │ (RLHF phase),       │ BERT, DINO,         │
│                  │ Sentiment analysis   │                      │ MuZero               │ Whisper              │
└──────────────────┴──────────────────────┴──────────────────────┴──────────────────────┴──────────────────────┘
```

### Detailed Descriptions

#### 3.1 Supervised Learning

The model learns a function **f: X → Y** from a labeled dataset of input-output pairs. The objective is to minimize a loss function (e.g., cross-entropy for classification, MSE for regression) over the training distribution, with the aim of generalizing to unseen data.

**Key subtypes:**
- **Classification**: Predict discrete labels (spam vs. ham, cat vs. dog, disease diagnosis).
- **Regression**: Predict continuous values (house prices, temperature, stock price).
- **Structured prediction**: Output is a structured object (sequence labeling, parsing, image segmentation).

**Modern deep supervised learning** dominates benchmarks when large labeled datasets are available. Transfer learning (pretrain + finetune) has dramatically reduced labeled data requirements.

#### 3.2 Unsupervised Learning

No labels are provided. The model discovers hidden structure, patterns, or representations in the data.

**Key subtypes:**
- **Clustering**: Group similar data points (K-Means, DBSCAN, spectral clustering).
- **Dimensionality reduction**: Project high-dimensional data to lower dimensions while preserving structure (PCA, t-SNE, UMAP, autoencoders).
- **Density estimation**: Model the probability distribution of the data (GMM, normalizing flows, VAEs).
- **Anomaly detection**: Identify data points that deviate from learned normal patterns.

#### 3.3 Reinforcement Learning

An **agent** interacts with an **environment**, taking **actions** and receiving **rewards**. The objective is to learn a **policy** **π(a|s)** that maximizes the expected cumulative reward (return).

**Key concepts:**
- **Markov Decision Process (MDP)**: Formal framework — states S, actions A, transitions P, rewards R.
- **Exploration vs. Exploitation**: Balancing trying new actions vs. leveraging known good actions.
- **Value functions**: V(s) and Q(s, a) estimate expected future return.
- **Policy gradient methods**: Directly optimize the policy (REINFORCE, PPO, A3C).
- **Model-based RL**: Learn the environment dynamics and plan; model-free RL: learn value/policy directly.

**Deep RL**: Neural networks approximate the policy or value function. Milestones: DQN (Atari), AlphaGo, PPO (used in RLHF for LLMs).

#### 3.4 Self-Supervised Learning (SSL)

The model generates its own supervision signal from the input data, typically via **pretext tasks** — artificial prediction problems whose solution requires understanding the data's structure.

**Key pretext tasks:**
- **Masked language modeling (MLM)**: Predict masked tokens in text — used by BERT.
- **Next-token prediction (NTP)**: Predict the next token given preceding tokens — used by GPT.
- **Contrastive learning**: Learn representations where similar pairs are close and dissimilar pairs are far (SimCLR, CLIP).
- **Masked image modeling (MIM)**: Predict masked patches of an image (MAE, BEiT).

SSL has become the dominant **pretraining** paradigm: massive models are pretrained on unlabeled data via SSL, then finetuned or prompted for downstream tasks. This is the foundation of LLMs and foundation models.

---

## 4. Core Mathematical Foundations

### Mind Map

```
                              ┌──────────────────────┐
                              │   MATHEMATICAL        │
                              │   FOUNDATIONS OF      │
                              │   AI / ML / DL        │
                              └──────────┬───────────┘
                    ┌────────────────────┼────────────────────┐
                    │                     │                     │
          ┌─────────▼──────────┐ ┌───────▼─────────┐ ┌────────▼────────┐
          │  LINEAR ALGEBRA    │ │   CALCULUS &     │ │  PROBABILITY &  │
          │                    │ │   OPTIMIZATION   │ │  STATISTICS     │
          │ • Vectors & Matrices│ │                  │ │                  │
          │ • Matrix Multiply  │ │ • Derivatives    │ │ • Bayes' Theorem │
          │   (core of NNs)    │ │ • Gradients      │ │ • Distributions  │
          │ • Eigenvalues/     │ │ • Chain Rule     │ │ • MLE / MAP     │
          │   Eigenvectors     │ │   (backprop!)    │ │ • Expectation    │
          │ • SVD / PCA        │ │ • Partial Diffs  │ │ • Variance/Bias  │
          │ • Tensor Ops       │ │ • Jacobian/      │ │ • Hypothesis     │
          │ • Norms (L1,L2,Fro)│ │   Hessian        │ │   Testing        │
          │ • LU, QR, Cholesky │ │ • Convexity      │ │ • Bayesian Infr. │
          └─────────┬──────────┘ │ • SGD, Adam,     │ │ • Markov Chains  │
                    │            │   RMSProp         │ │ • MCMC            │
                    │            └───────┬──────────┘ └────────┬────────┘
                    │                    │                     │
                    └────────────┬───────┘─────────────────────┘
                                 │
                    ┌────────────▼────────────────────────────────────┐
                    │           INFORMATION THEORY                    │
                    │                                                │
                    │  • Shannon Entropy: H(X) = -Σ p(x) log p(x)   │
                    │  • Cross-Entropy: H(p,q) = -Σ p(x) log q(x)   │
                    │  • KL Divergence: D_KL(p‖q)                    │
                    │  • Mutual Information: I(X;Y)                   │
                    │  • Rate-Distortion Theory                        │
                    │  • Data Processing Inequality                    │
                    │                                                │
                    │  ► Cross-entropy = loss function for            │
                    │    classification & language modeling            │
                    │  ► KL divergence = regularizer, VAE loss          │
                    │  ► Entropy = uncertainty, exploration bonus in RL │
                    └─────────────────────────────────────────────────┘
                                 │
               ┌─────────────────┼──────────────────┐
               │                 │                   │
    ┌──────────▼─────┐  ┌───────▼──────────┐  ┌────▼───────────────┐
    │  APPLIED TO:   │  │  APPLIED TO:     │  │  APPLIED TO:       │
    │                │  │                  │  │                    │
    │  • Affine      │  │  • Backprop      │  │  • Naive Bayes     │
    │    transforms  │  │  • Gradient      │  │  • Gaussian MMs    │
    │  • Attention   │  │    descent       │  │  • Hidden Markov   │
    │    = QK^T V    │  │  • Learning      │  │    Models          │
    │  • Convolutions│  │    rates & sched │  │  • Bayesian Opt.    │
    │  • Embeddings  │  │  • Lagrangians   │  │  • VAE posterior   │
    │  • BatchNorm   │  │    (duality)     │  │  • Dirichlet prior │
    └────────────────┘  └──────────────────┘  └────────────────────┘
```

### Detailed Mathematical Areas

#### 4.1 Linear Algebra — The Language of Neural Networks

Every neural network operation is a sequence of linear algebra operations:

- **Forward pass**: `z = Wx + b` — affine transform (matrix multiply + bias)
- **Attention**: `Attention(Q,K,V) = softmax(QK^T / √d_k) V` — multiplies three matrices
- **Convolution**: Expressible as a Toeplitz matrix multiplication
- **Backpropagation**: Chain rule applied via matrix/tensor derivatives → Jacobians

**Key objects:**
| Object | Notation | Role in ML |
|--------|----------|------------|
| Vector | **x** ∈ ℝⁿ | Data point, embedding |
| Matrix | **W** ∈ ℝᵐˣⁿ | Weight matrix |
| Tensor | 𝒯 ∈ ℝᵈ¹ˣᵈ²ˣ...ˣᵈᵏ | Multi-dimensional array (images, batches) |
| Scalar | b ∈ ℝ | Bias term |
| Eigenvalues | λ | Spectral properties, convergence analysis |
| Norm | ‖x‖ | Regularization (L1 sparse, L2 weight decay) |

**Critical decompositions:**
- **SVD**: `A = UΣV^T` — basis of PCA, low-rank approximation, model compression
- **Eigendecomposition**: Basis of spectral clustering, PageRank, convergence proofs
- **QR decomposition**: Stable solving of linear systems

#### 4.2 Calculus & Optimization — How Networks Learn

Learning IS optimization. The entire training loop is:

```
repeat:
    1. Forward pass:     compute L(θ) w.r.t. current parameters θ
    2. Backward pass:    compute ∇_θ L(θ) via backpropagation (reverse-mode autodiff)
    3. Update:          θ ← θ - η ∇_θ L(θ)        (SGD)
                       θ ← θ - η · m̂_t / (√v̂_t + ε)   (Adam)
```

**Key concepts:**
- **Multivariable calculus**: Partial derivatives, gradients, directional derivatives.
- **Chain rule**: The backbone of backpropagation — composing Jacobians layer by layer in reverse mode.
- **Jacobian matrix**: `J_ij = ∂f_i/∂x_j` — generalizes gradient to vector-valued functions.
- **Hessian matrix**: `H_ij = ∂²L/(∂θ_i ∂θ_j)` — second-order curvature information; used in Newton's method, analysis of critical points.
- **Convexity**: A function is convex iff its Hessian is positive semidefinite everywhere. Convex problems have a unique global minimum — but deep neural network loss surfaces are **non-convex**, with saddle points, local minima, and flat regions.
- **Learning rate schedules**: Cosine annealing, warmup, step decay — geometry-aware learning rate strategies.

#### 4.3 Probability & Statistics — Modeling Uncertainty

Machine learning is fundamentally about reasoning under uncertainty. Probability provides the formal framework.

**Core theorems:**
- **Bayes' Theorem**: `P(h|D) = P(D|h) P(h) / P(D)` — the foundation of Bayesian inference, relating posterior, likelihood, and prior.
- **Law of Large Numbers**: Sample averages converge to expected values — justifies MLE.
- **Central Limit Theorem**: Sums of i.i.d. random variables converge to Gaussian — explains why Gaussian noise is ubiquitous.

**Key distributions in ML:**
| Distribution | Use |
|--------------|-----|
| Gaussian 𝒩(μ, σ²) | Noise models, VAE latent space, weight initialization |
| Categorical | Classification output (softmax) |
| Bernoulli | Binary classification (sigmoid) |
| Dirichlet | Prior over categorical distributions (topic models, LDA) |
| Poisson | Count data |
| Multivariate Normal | Gaussian mixture models, generative models |

**Estimation:**
- **Maximum Likelihood Estimation (MLE)**: `θ̂ = argmax_θ P(D|θ)` — find parameters that make observed data most probable.
- **Maximum A Posteriori (MAP)**: `θ̂ = argmax_θ P(θ|D) = argmax_θ P(D|θ) P(θ)` — MLE with a prior; equivalent to MLE + L2 regularization under Gaussian prior.

**Bias-Variance Tradeoff:**
```
Expected Error = Bias² + Variance + Irreducible Noise

  High bias (underfitting):   ○○○○○○○○○○             Simple model, misses patterns
  High variance (overfitting): ●●●●○○○○●●             Complex model, fits noise
  Good balance:               ●●●●●●●●●●             Appropriate complexity
```

#### 4.4 Information Theory — Quantifying Information

Information theory connects directly to loss functions and model evaluation.

- **Shannon Entropy**: `H(X) = -Σ p(x) log p(x)` — measures uncertainty in a random variable. Higher entropy = more uncertainty.
- **Cross-Entropy Loss**: `L_CE = -Σ y log(ŷ)` — the standard loss for classification and language modeling. Minimizing cross-entropy is equivalent to maximizing log-likelihood under the model.
- **Kullback-Leibler Divergence**: `D_KL(p‖q) = Σ p(x) log(p(x)/q(x))` — measures how distribution q diverges from reference p. Non-negative, asymmetric. Used in VAE loss, knowledge distillation, policy regularization.
- **Mutual Information**: `I(X;Y) = H(X) - H(X|Y)` — measures the reduction in uncertainty about X from knowing Y. Used in InfoMax principle for self-supervised learning.

---

## 5. Key Milestones and Breakthroughs

```
  YEAR  MILESTONE                         IMPACT
  ─────┬──────────────────────────────────┬───────────────────────────────────────────┐
  1957 │ Perceptron (Rosenblatt)          │ First learnable neural model; proved linear │
       │                                  │ separability limits → spurred AI winter     │
  1986 │ Backpropagation (Rumelhart et al)│ Enabled training of multi-layer networks;   │
       │                                  │ resolved Perceptron limitations              │
  1989 │ LeNet / CNN (LeCun)              │ End-to-end learned visual features;         │
       │                                  │ foundation of computer vision                │
  1997 │ LSTM (Hochreiter & Schmidhuber)  │ Solved vanishing gradient for sequences;    │
       │                                  │ dominated NLP/sequence tasks for 20 years   │
  1997 │ Deep Blue beats Kasparov         │ Symbolic/search-based AI milestone;         │
       │                                  │ NOT learning-based                           │
  2006 │ Deep Belief Nets (Hinton)        │ Layer-wise pretraining; revival of deep     │
       │                                  │ learning research                           │
  2012 │ AlexNet wins ImageNet            │ Proof that deep CNNs + GPUs dominate vision;│
       │                                  │ started the deep learning revolution         │
  2014 │ GANs (Goodfellow)                │ Adversarial training paradigm; enables     │
       │                                  │ photorealistic generation                   │
  2014 │ Seq2Seq (Sutskever et al)        │ Encoder-decoder for neural translation;     │
       │                                  │ foundation of modern sequence models         │
  2015 │ DQN / Atari (Mnih et al)         │ Deep RL learns from raw pixels;             │
       │                                  │ human-level performance on Atari games       │
  2016 │ AlphaGo beats Lee Sedol          │ RL + search surpasses human expertise       │
       │                                  │ in the most complex board game               │
  2017 │ TRANSFORMER (Vaswani et al)      │ ★ PARADIGM SHIFT ★ — eliminates recurrence;│
       │  "Attention Is All You Need"     │ enables massive parallelism & scaling        │
  2018 │ BERT (Devlin et al)              │ Bidirectional pretraining; MLM objective;   │
       │                                  │ NLP transfer learning standard               │
  2018 │ GPT-1 (Radford et al)            │ Unidirectional pretraining; demonstrates    │
       │                                  │ power of next-token prediction at scale      │
  2020 │ GPT-3 (Brown et al, 175B)        │ In-context (few-shot) learning; emergent    │
       │                                  │ abilities from scale                         │
  2022 │ ChatGPT (OpenAI)                 │ RLHF-aligned LLM goes mainstream;            │
       │                                  │ catalytic moment for AI adoption             │
  2022 │ Stable Diffusion                 │ Open-source diffusion model; democratizes   │
       │                                  │ high-quality image generation               │
  2023 │ GPT-4 (OpenAI)                   │ Multimodal reasoning (text + image);        │
       │                                  │ strong performance on professional exams     │
  2023 │ Llama 2 (Meta)                   │ Open-weight high-quality LLM; enables       │
       │                                  │ vibrant open-source ecosystem                │
  2024 │ Mixture-of-Experts (MoE)         │ Sparse activation; compute efficiency at    │
       │  Mixtral, rumored GPT-4 arch    │ scale; only activate relevant "experts"      │
  2024 │ Reasoning models (o1, o3)        │ Chain-of-thought at inference time;          │
       │                                  │ RL-trained "thinking" before answering      │
  2024 │ Agentic AI frameworks            │ LLMs orchestrate tool use, planning,        │
       │                                  │ multi-step reasoning, web browsing          │
  2025 │ Continued scaling & efficiency   │ Long context (>1M tokens), distilled models, │
       │                                  │ neuromorphic HW, constitutional AI           │
  ─────┴──────────────────────────────────┴─────────────────────────────────────────────┘
```

### The Transformer Architecture — Detail

The single most impactful architecture since 2017:

```
  INPUT TOKENS ──► [Embedding + Positional Encoding] ──►
                                                       │
                                            ┌──────────▼──────────┐
                                            │   MULTI-HEAD         │
                                            │   SELF-ATTENTION     │
                                            │                      │
                                            │   Q = XW_Q           │
                                            │   K = XW_K           │
                                            │   V = XW_V           │
                                            │                      │
                                            │   Attn(Q,K,V) =      │
                                            │     softmax(QK^T/√d)V │
                                            └──────────┬──────────┘
                                                       │
                                            ┌──────────▼──────────┐
                                            │   ADD & NORM         │  ◄── Residual connection
                                            └──────────┬──────────┘
                                                       │
                                            ┌──────────▼──────────┐
                                            │   FEED-FORWARD      │
                                            │   FFN(x) =          │
                                            │     max(0, xW₁+b₁)W₂│   ◄── 2-layer MLP with ReLU/GELU
                                            │          + b₂       │
                                            └──────────┬──────────┘
                                                       │
                                            ┌──────────▼──────────┐
                                            │   ADD & NORM         │  ◄── Residual connection
                                            └──────────┬──────────┘
                                                       │
                                                [Repeat N×]
                                                       │
                                            ┌──────────▼──────────┐
                                            │   LINEAR + SOFTMAX   │
                                            └──────────┬──────────┘
                                                       │
                                                  OUTPUT PROBS
```

**Why Transformers replaced RNNs:**
1. **Parallelizable**: No sequential dependency — all positions computed simultaneously
2. **Long-range dependencies**: Direct paths between any two tokens via attention
3. **Scalable**: Architecturally simple, amenable to GPU/TPU acceleration
4. **Flexible**: Same architecture works for language, vision (ViT), audio, protein sequences, etc.

---

## 6. The Full AI Landscape Taxonomy

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              AI LANDSCAPE TAXONOMY                                       │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  ┌─── SYMBOLIC / GOFAI ────────────────────────────────────────────────────────────┐    │
│  │  • Expert Systems (MYCIN, Dendral)        • Knowledge Graphs (Wikidata, DBpedia)│    │
│  │  • Logic Programming (Prolog)             • Ontologies & Taxonomies             │    │
│  │  • Rule-Based Systems                     • Planning (STRIPS, PDDL)            │    │
│  │  • Constraint Satisfaction               • Automated Theorem Proving           │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                         │
│  ┌─── CLASSICAL MACHINE LEARNING ─────────────────────────────────────────────────┐    │
│  │                                                                                 │    │
│  │  SUPERVISED              UNSUPERVISED          ENSEMBLE            OTHER          │    │
│  │  ├─ Linear Regression    ├─ K-Means           ├─ Random Forest    ├─ Naive Bayes │    │
│  │  ├─ Logistic Regression  ├─ DBSCAN             ├─ Gradient Boost   ├─ k-NN       │    │
│  │  ├─ SVM                 ├─ Gaussian Mixtures  ├─ XGBoost           ├─ HMM        │    │
│  │  ├─ Decision Trees       ├─ PCA / ICA          ├─ LightGBM         ├─ CRF        │    │
│  │  └─ LDA / QDA           ├─ t-SNE / UMAP       └─ CatBoost         └─ PRM        │    │
│  │                          └─ Autoencoders                                       │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                         │
│  ┌─── DEEP LEARNING ──────────────────────────────────────────────────────────────┐    │
│  │                                                                                 │    │
│  │  ARCHITECTURES              TRAINING PARADIGMS           REGULARIZATION         │    │
│  │  ├─ CNN (ResNet, EfficientNet) ├─ Supervised (CE, MSE)   ├─ Dropout            │    │
│  │  ├─ RNN / LSTM / GRU          ├─ Self-supervised (MLM,   ├─ Batch/Layer Norm   │    │
│  │  ├─ Transformer (Attn-only)    │   NTP, Contrastive)     ├─ Weight Decay       │    │
│  │  ├─ Hybrid (CNN+Trans)         ├─ Reinforcement (RLHF,    ├─ Data Augmentation  │    │
│  │  ├─ GNN (GAT, GraphSAGE)       │   PPO, DPO)             ├─ Early Stopping     │    │
│  │  ├─ State Space Models (Mamba)  ├─ Distillation           └─ Stochastic Depth   │    │
│  │  └─ Diffusion U-Net            └─ Curriculum Learning                            │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                         │
│  ┌─── GENERATIVE AI ───────────────────────────────────────────────────────────────┐    │
│  │                                                                                 │    │
│  │  MODALITY ─────┬── TEXT ────────────────────────────────────────────────────    │    │
│  │                │    LLMs: GPT-4, Claude, Gemini, Llama, Mistral                 │    │
│  │                │    Paradigms: Autoregressive (next-token), Encoder-Decoder     │    │
│  │                │    Alignment: RLHF, DPO, Constitutional AI, RLAIF              │    │    │
│  │                │    Techniques: Chain-of-thought, Few-shot, Fine-tuning, LoRA   │    │
│  │                │                                                                │    │
│  │                ├── IMAGE ──────────────────────────────────────────────────────  │    │
│  │                │    Diffusion: Stable Diffusion, DALL·E, Midjourney, Imagen    │    │
│  │                │    GANs: StyleGAN, CycleGAN                                  │    │
│  │                │    Autoregressive: Parti                                     │    │
│  │                │                                                                │    │
│  │                ├── AUDIO ────────────────────────────────────────────────────── │    │
│  │                │    TTS: VALL-E, Bark, ElevenLabs                              │    │
│  │                │    Music: MusicLM, AudioLDM, Udio, Suno                      │    │
│  │                │                                                                │    │
│  │                ├── VIDEO ────────────────────────────────────────────────────── │    │
│  │                │    Sora, Veo, Runway Gen-2, Pika, Kling                      │    │
│  │                │                                                                │    │
│  │                ├── CODE ─────────────────────────────────────────────────────── │    │
│  │                │    Codex, GitHub Copilot, Code Llama, DeepSeek-Coder          │    │
│  │                │                                                                │    │
│  │                ├── MULTIMODAL ──────────────────────────────────────────────── │    │
│  │                │    GPT-4V, Gemini, LLaVA, CLIP, SigLIP, Florence            │    │
│  │                │                                                                │    │
│  │                ├── 3D / SPATIAL ─────────────────────────────────────────────── │    │
│  │                │    Point-E, Shap-E, DreamGaussian, LRM                      │    │
│  │                │                                                                │    │
│  │                └── SCIENTIFIC ──────────────────────────────────────────────── │    │
│  │                     AlphaFold, ESMFold, DiffDock, molecule generation           │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                         │
│  ┌─── REINFORCEMENT LEARNING ─────────────────────────────────────────────────────┐    │
│  │  ├─ Value-based:  DQN, Double DQN, Dueling DQN, Rainbow                       │    │
│  │  ├─ Policy-based: REINFORCE, A3C, PPO, SAC, TD3                               │    │
│  │  ├─ Model-based:  MuZero, Dreamer, AlphaZero                                  │    │
│  │  ├─ Multi-agent:  MADDPG, QMIX                                                │    │
│  │  └─ Offline RL:   Decision Transformer, Conservative Q-Learning               │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                         │
│  ┌─── EMERGING PARADIGMS (2024–2025+) ────────────────────────────────────────────┐    │
│  │  ├─ Agentic AI:        LLMs with tool use, planning, memory, web browsing      │    │
│  │  ├─ Mixture-of-Experts: Sparse activation for compute efficiency (Mixtral, MoE)│    │
│  │  ├─ Reasoning models:   o1, o3, DeepSeek-R1 — think-before-answering via RL    │    │
│  │  ├─ Retrieval-Augmented: RAG — grounding LLM outputs in external knowledge     │    │
│  │  ├─ Multimodal fusion:  Unified models handling text, image, audio, video, code  │    │
│  │  ├─ On-device / Edge:   Quantized, distilled models running on phones/edge     │    │
│  │  ├─ Mechanistic interpretability: Reverse-engineering neural network circuits   │    │
│  │  ├─ Constitutional AI: Self-improving alignment through critiquing outputs     │    │
│  │  ├─ Neuromorphic HW:    Brain-inspired chips (Intel Loihi, IBM TrueNorth)      │    │
│  │  └─ AI Safety:          Red-teaming, guardrails, formal verification, alignment │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                         │
│  ┌─── INFRASTRUCTURE & ECOSYSTEM ─────────────────────────────────────────────────┐    │
│  │                                                                                 │    │
│  │  FRAMEWORKS          HARDWARE           DATASETS           PLATFORMS           │    │
│  │  ├─ PyTorch          ├─ NVIDIA H100/B200  ├─ ImageNet      ├─ Hugging Face     │    │
│  │  ├─ TensorFlow/JAX   ├─ Google TPU v5     ├─ Common Crawl  ├─ OpenAI API       │    │
│  │  ├─ MXNet            ├─ AMD MI300X        ├─ The Pile       ├─ AWS Bedrock      │    │
│  │  ├─ ONNX             ├─ Apple Neural Eng.  ├─ RedPajama    ├─ GCP Vertex AI    │    │
│  │  └─ Candle (Rust)    └─ Groq LPU           ├─ SlimPajama   └─ Azure AI         │    │
│  │                                               └─ FineWeb                         │    │
│  │                                                                                 │    │
│  │  TRAINING TECHNIQUES       EFFICIENCY TECHNIQUES                                │    │
│  │  ├─ Distributed (DDP, FSDP)   ├─ Quantization (INT8, INT4, FP8, GPTQ)        │    │
│  │  ├─ Mixed Precision (AMP)      ├─ Pruning (magnitude, structured, SparseGPT)  │    │
│  │  ├─ Gradient Accumulation     ├─ Knowledge Distillation                       │    │
│  │  ├─ FlashAttention            ├─ LoRA / QLoRA (parameter-efficient finetune)  │    │
│  │  └─ Pipeline/Tensor Parallel  └─ Speculative Decoding                          │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### AI Paradigm Evolution Summary

```
  Paradigm              Era           Key Insight                    Limitation
  ──────────────────── ────────────── ─────────────────────────────── ──────────────────────
  Symbolic AI           1950s–1980s   Knowledge = rules + facts      Brittle, doesn't scale
  Statistical ML       1990s–2010s   Learn patterns from data       Feature engineering
  Deep Learning         2012–2020     Learn features end-to-end      Data-hungry, opaque
  Foundation Models     2020–2024     Scale + pretrain + adapt       Alignment, cost
  Agentic AI           2024–present   LLMs + tools + planning       Reliability, safety
  ──────────────────── ────────────── ─────────────────────────────── ──────────────────────
```

### Scaling Laws — The Empirical Foundation of Modern AI

Three scaling laws govern modern deep learning:

1. **Kaplan et al. (2020)**: Language model performance scales as a **power law** with model size, dataset size, and compute: `L(N) ∝ N^{-0.076}`, `L(D) ∝ D^{-0.095}`, where N = parameters, D = tokens.

2. **Chinchilla (Hoffmann et al., 2022)**: For a given compute budget, models and data should scale **equally** — many overparameterized models (e.g., original GPT-3) were **undertrained**. Optimal: ~20 tokens per parameter.

3. **Emergent abilities (Wei et al., 2022)**: Certain capabilities (chain-of-thought reasoning, multi-step arithmetic) appear **abruptly** at scale, not gradually — suggesting qualitative shifts with quantitative scaling.

```
  Loss
   │
   │ ╲  Small model
   │   ╲
   │    ╲
   │     ╲───────── Medium model
   │              ╲
   │                ╲
   │                  ╲──────── Large model
   │                         ╲
   │                           ╲──────── Frontier model
   │
   └───────────────────────────────────────────────► Compute (FLOPs)
        (Power law: Loss ∝ Compute^{-α}, α ≈ 0.05)
```

---

## Cross-Reference: How It All Connects

```
  Mathematical Foundations          Core Algorithms              Applications
  ──────────────────────          ─────────────────          ─────────────────
  Linear Algebra ─────────────► Matrix multiply ────────► Neural net forward pass
  Calculus / Chain Rule ──────► Backpropagation ────────► Training all deep models
  Probability / Bayes ────────► Naive Bayes / VAE ─────► Classification, generation
  Information Theory ────────► Cross-entropy loss ────► LLM training objective
  Optimization (convex/n't) ──► SGD / Adam ─────────────► Convergence & generalization
  Graph Theory ───────────────► GNNs ──────────────────► Molecular, social networks
  Dynamical Systems ──────────► SSMs / RNNs ───────────► Time series, language
  Functional Analysis ────────► Kernel methods ────────► SVMs, Gaussian processes
```

---

*This document provides the foundational context for understanding the subsequent sections in this series. The key takeaway: AI is a broad discipline; ML is its data-driven subset; DL is ML's representation-learning engine; and GenAI is DL's generative frontier. The mathematical foundations (linear algebra, calculus, probability, information theory) underpin all of these, and the evolution from symbolic systems to agentic workflows represents a continuous arc of increasing capability driven by scale, data, and architectural innovation.*

---

## Real References

### Foundational AI Papers

1. Turing, A.M., "Computing Machinery and Intelligence", *Mind*, 59(236):433–460, 1950. DOI: [10.1093/mind/LIX.236.433](https://doi.org/10.1093/mind/LIX.236.433)

2. McCarthy, J., Minsky, M.L., Rochester, N., Shannon, C.E., "A Proposal for the Dartmouth Summer Research Project on Artificial Intelligence", 1955. Reprinted in *AI Magazine*, 27(4):12, 2006. DOI: [10.1609/aimag.v27i4.1904](https://doi.org/10.1609/aimag.v27i4.1904)

3. Rosenblatt, F., "The Perceptron: A Probabilistic Model for Information Storage and Organization in the Brain", *Psychological Review*, 65(6):386–408, 1958. DOI: [10.1037/h0042519](https://doi.org/10.1037/h0042519)

4. Minsky, M., Papert, S., *Perceptrons: An Introduction to Computational Geometry*, MIT Press, 1969. ISBN: 978-0262630221

5. Weizenbaum, J., "ELIZA—A Computer Program for the Study of Natural Language Communication Between Man and Machine", *Communications of the ACM*, 9(1):36–45, 1966. DOI: [10.1145/365153.365168](https://doi.org/10.1145/365153.365168)

### Neural Network Foundations

6. Rumelhart, D.E., Hinton, G.E., Williams, R.J., "Learning Representations by Back-Propagating Errors", *Nature*, 323(6088):533–536, 1986. DOI: [10.1038/323533a0](https://doi.org/10.1038/323533a0)

7. LeCun, Y., Boser, B., Denker, J.S., Henderson, D., Howard, R.E., Hubbard, W., Jackel, L.D., "Backpropagation Applied to Handwritten Zip Code Recognition", *Neural Computation*, 1(4):541–551, 1989. DOI: [10.1162/neco.1989.1.4.541](https://doi.org/10.1162/neco.1989.1.4.541)

8. Hochreiter, S., Schmidhuber, J., "Long Short-Term Memory", *Neural Computation*, 9(8):1735–1780, 1997. DOI: [10.1162/neco.1997.9.8.1735](https://doi.org/10.1162/neco.1997.9.8.1735)

9. Hinton, G.E., Osindero, S., Teh, Y.W., "A Fast Learning Algorithm for Deep Belief Nets", *Neural Computation*, 18(7):1527–1554, 2006. DOI: [10.1162/neco.2006.18.7.1527](https://doi.org/10.1162/neco.2006.18.7.1527)

10. Glorot, X., Bengio, Y., "Understanding the Difficulty of Training Deep Feedforward Neural Networks", *Proc. AISTATS*, 2010. URL: [http://proceedings.mlr.press/v9/glorot10a.html](http://proceedings.mlr.press/v9/glorot10a.html)

### Classical Machine Learning

11. Cortes, C., Vapnik, V., "Support-Vector Networks", *Machine Learning*, 20(3):273–297, 1995. DOI: [10.1007/BF00994018](https://doi.org/10.1007/BF00994018)

12. Freund, Y., Schapire, R.E., "A Decision-Theoretic Generalization of On-Line Learning and an Application to Boosting", *Journal of Computer and System Sciences*, 55(1):119–139, 1997. DOI: [10.1006/jcss.1997.1504](https://doi.org/10.1006/jcss.1997.1504)

13. Breiman, L., "Random Forests", *Machine Learning*, 45(1):5–32, 2001. DOI: [10.1023/A:1010933404324](https://doi.org/10.1023/A:1010933404324)

14. Chen, T., Guestrin, C., "XGBoost: A Scalable Tree Boosting System", *Proc. KDD*, 2016. DOI: [10.1145/2939672.2939785](https://doi.org/10.1145/2939672.2939785)

15. MacQueen, J., "Some Methods for Classification and Analysis of Multivariate Observations", *Proc. Berkeley Symposium on Mathematical Statistics and Probability*, 1967.

16. van der Maaten, L., Hinton, G.E., "Visualizing Data Using t-SNE", *Journal of Machine Learning Research*, 9:2579–2605, 2008. URL: [https://jmlr.org/papers/v9/vandermaaten08a.html](https://jmlr.org/papers/v9/vandermaaten08a.html)

17. McInnes, L., Healy, J., Melville, J., "UMAP: Uniform Manifold Approximation and Projection for Dimension Reduction", arXiv:1802.03426, 2018. URL: [https://arxiv.org/abs/1802.03426](https://arxiv.org/abs/1802.03426)

### Deep Learning Revolution

18. Krizhevsky, A., Sutskever, I., Hinton, G.E., "ImageNet Classification with Deep Convolutional Neural Networks", *Advances in Neural Information Processing Systems (NeurIPS)*, 25, 2012. URL: [https://papers.nips.cc/paper/2012/hash/c399862d3b9d6b76c8436e924a68c45b-Abstract.html](https://papers.nips.cc/paper/2012/hash/c399862d3b9d6b76c8436e924a68c45b-Abstract.html)

19. He, K., Zhang, X., Ren, S., Sun, J., "Deep Residual Learning for Image Recognition", *Proc. CVPR*, 2016. DOI: [10.1109/CVPR.2016.90](https://doi.org/10.1109/CVPR.2016.90). arXiv:1512.03385

20. Tan, M., Le, Q.V., "EfficientNet: Rethinking Model Scaling for Convolutional Neural Networks", *Proc. ICML*, 2019. arXiv:1905.11946

21. Mikolov, T., Chen, K., Corrado, G., Dean, J., "Efficient Estimation of Word Representations in Vector Space", arXiv:1301.3781, 2013. URL: [https://arxiv.org/abs/1301.3781](https://arxiv.org/abs/1301.3781)

22. Pennington, J., Socher, R., Manning, C.D., "GloVe: Global Vectors for Word Representation", *Proc. EMNLP*, 2014. DOI: [10.3115/v1/D14-1162](https://doi.org/10.3115/v1/D14-1162)

### Generative Models

23. Goodfellow, I., Pouget-Abadie, J., Mirza, M., Xu, B., Warde-Farley, D., Ozair, S., Courville, A., Bengio, Y., "Generative Adversarial Nets", *Advances in Neural Information Processing Systems (NeurIPS)*, 27, 2014. URL: [https://proceedings.neurips.cc/paper/2014/hash/5ca3e9b122f61f8f06494c97b1afccf3-Abstract.html](https://proceedings.neurips.cc/paper/2014/hash/5ca3e9b122f61f8f06494c97b1afccf3-Abstract.html)

24. Kingma, D.P., Welling, M., "Auto-Encoding Variational Bayes", *Proc. ICLR*, 2014. arXiv:1312.6114

25. Ho, J., Jain, A., Abbeel, P., "Denoising Diffusion Probabilistic Models", *Advances in Neural Information Processing Systems (NeurIPS)*, 33, 2020. arXiv:2006.11239

26. Rombach, R., Blattmann, A., Lorenz, D., Esser, P., Ommer, B., "High-Resolution Image Synthesis with Latent Diffusion Models", *Proc. CVPR*, 2022. arXiv:2112.10752

### Sequence-to-Sequence and Attention

27. Sutskever, I., Vinyals, O., Le, Q.V., "Sequence to Sequence Learning with Neural Networks", *Advances in Neural Information Processing Systems (NeurIPS)*, 27, 2014. arXiv:1409.3215

28. Bahdanau, D., Cho, K., Bengio, Y., "Neural Machine Translation by Jointly Learning to Align and Translate", *Proc. ICLR*, 2015. arXiv:1409.0473

29. Vaswani, A., Shazeer, N., Parmar, N., Uszkoreit, J., Jones, L., Gomez, A.N., Kaiser, Ł., Polosukhin, I., "Attention Is All You Need", *Advances in Neural Information Processing Systems (NeurIPS)*, 30, 2017. arXiv:1706.03762. URL: [https://arxiv.org/abs/1706.03762](https://arxiv.org/abs/1706.03762)

### Language Models

30. Radford, A., Narasimhan, K., Salimans, T., Sutskever, I., "Improving Language Understanding by Generative Pre-Training", OpenAI, 2018. URL: [https://cdn.openai.com/research-covers/language-unsupervised/language_understanding_paper.pdf](https://cdn.openai.com/research-covers/language-unsupervised/language_understanding_paper.pdf)

31. Devlin, J., Chang, M.W., Lee, K., Toutanova, K., "BERT: Pre-training of Deep Bidirectional Transformers for Language Understanding", *Proc. NAACL-HLT*, 2019. arXiv:1810.04805. DOI: [10.18653/v1/N19-1423](https://doi.org/10.18653/v1/N19-1423)

32. Brown, T.B., Mann, B., Ryder, N., et al., "Language Models are Few-Shot Learners", *Advances in Neural Information Processing Systems (NeurIPS)*, 33, 2020. arXiv:2005.14165. URL: [https://arxiv.org/abs/2005.14165](https://arxiv.org/abs/2005.14165)

33. OpenAI, "GPT-4 Technical Report", arXiv:2303.08774, 2023. URL: [https://arxiv.org/abs/2303.08774](https://arxiv.org/abs/2303.08774)

34. Touvron, H., Martin, L., Stone, K., et al., "Llama 2: Open Foundation and Fine-Tuned Chat Models", arXiv:2307.09288, 2023. URL: [https://arxiv.org/abs/2307.09288](https://arxiv.org/abs/2307.09288)

35. Jiang, A.Q., Sablayrolles, A., Roux, A., et al., "Mixtral of Experts", arXiv:2401.04088, 2024. URL: [https://arxiv.org/abs/2401.04088](https://arxiv.org/abs/2401.04088)

### Scaling Laws

36. Kaplan, J., McCandlish, S., Henighan, T., Brown, T.B., Chess, B., Child, R., Gray, S., Radford, A., Wu, J., Amodei, D., "Scaling Laws for Neural Language Models", arXiv:2001.08361, 2020. URL: [https://arxiv.org/abs/2001.08361](https://arxiv.org/abs/2001.08361)

37. Hoffmann, J., Borgeaud, S., Mensch, A., et al., "Training Compute-Optimal Large Language Models" (Chinchilla), arXiv:2203.15556, 2022. URL: [https://arxiv.org/abs/2203.15556](https://arxiv.org/abs/2203.15556)

38. Wei, J., Tay, Y., Bommasani, R., et al., "Emergent Abilities of Large Language Models", *Transactions on Machine Learning Research*, 2022. arXiv:2206.07682

### Reinforcement Learning

39. Mnih, V., Kavukcuoglu, K., Silver, D., et al., "Human-Level Control Through Deep Reinforcement Learning", *Nature*, 518(7540):529–533, 2015. DOI: [10.1038/nature14236](https://doi.org/10.1038/nature14236)

40. Silver, D., Huang, A., Maddison, C.J., et al., "Mastering the Game of Go with Deep Neural Networks and Tree Search", *Nature*, 529(7587):484–489, 2016. DOI: [10.1038/nature16961](https://doi.org/10.1038/nature16961)

41. Silver, D., Schrittwieser, J., Simonyan, K., et al., "Mastering the Game of Go Without Human Knowledge", *Nature*, 550(7676):354–359, 2017. DOI: [10.1038/nature24270](https://doi.org/10.1038/nature24270)

42. Schulman, J., Wolski, F., Dhariwal, P., Radford, A., Klimov, O., "Proximal Policy Optimization Algorithms", arXiv:1707.06347, 2017. URL: [https://arxiv.org/abs/1707.06347](https://arxiv.org/abs/1707.06347)

43. Sutton, R.S., Barto, A.G., *Reinforcement Learning: An Introduction*, 2nd ed., MIT Press, 2018. ISBN: 978-0262039246. URL: [http://incompleteideas.net/book/the-book.html](http://incompleteideas.net/book/the-book.html)

### Alignment and RLHF

44. Ouyang, L., Wu, J., Jiang, X., et al., "Training language models to follow instructions with human feedback", *NeurIPS*, 2022. arXiv:2203.02155

45. Bai, Y., Jones, A., Ndousse, K., et al., "Training a Helpful and Harmless Assistant with Reinforcement Learning from Human Feedback", arXiv:2204.05862, 2022. URL: [https://arxiv.org/abs/2204.05862](https://arxiv.org/abs/2204.05862)

46. Rafailov, R., Sharma, A., Mitchell, E., Manning, C.D., Ermon, S., Finn, C., "Direct Preference Optimization: Your Language Model is Secretly a Reward Model", *NeurIPS*, 2023. arXiv:2305.18290

47. Bai, Y., Kadavath, S., Kundu, S., et al., "Constitutional AI: Harmlessness from AI Feedback", arXiv:2212.08073, 2022. URL: [https://arxiv.org/abs/2212.08073](https://arxiv.org/abs/2212.08073)

### Multimodal and Vision Models

48. Radford, A., Kim, J.W., Hallacy, C., et al., "Learning Transferable Visual Models From Natural Language Supervision" (CLIP), *Proc. ICML*, 2021. arXiv:2103.00020

49. Dosovitskiy, A., Beyer, L., Kolesnikov, A., et al., "An Image is Worth 16x16 Words: Transformers for Image Recognition at Scale" (ViT), *Proc. ICLR*, 2021. arXiv:2010.11929

50. Liu, H., Li, C., Wu, Q., Lee, Y.J., "Visual Instruction Tuning" (LLaVA), *NeurIPS*, 2023. arXiv:2304.08485

### Protein and Scientific AI

51. Jumper, J., Evans, R., Pritzel, A., et al., "Highly Accurate Protein Structure Prediction with AlphaFold", *Nature*, 596(7873):583–589, 2021. DOI: [10.1038/s41586-021-03819-2](https://doi.org/10.1038/s41586-021-03819-2)

### Self-Supervised Learning

52. He, K., Chen, X., Xie, S., Li, Y., Dollár, P., Girshick, R., "Masked Autoencoders Are Scalable Vision Learners" (MAE), *Proc. CVPR*, 2022. arXiv:2111.06377

53. Chen, T., Kornblith, S., Norouzi, M., Hinton, G.E., "A Simple Framework for Contrastive Learning of Visual Representations" (SimCLR), *Proc. ICML*, 2020. arXiv:2002.05709

54. Caron, M., Touvron, H., Misra, I., Jégou, H., Mairal, J., Bojanowski, P., Joulin, A., "Emerging Properties in Self-Supervised Vision Transformers" (DINO), *Proc. ICCV*, 2021. arXiv:2104.14294

### Code Generation

55. Chen, M., Tworek, J., Jun, H., et al., "Evaluating Large Language Models Trained on Code" (Codex), arXiv:2107.03374, 2021. URL: [https://arxiv.org/abs/2107.03374](https://arxiv.org/abs/2107.03374)

56. Rozière, B., Gehring, J., Gloeckle, F., et al., "Code Llama: Open Foundation Models for Code", arXiv:2308.12950, 2023. URL: [https://arxiv.org/abs/2308.12950](https://arxiv.org/abs/2308.12950)

### Reasoning Models

57. OpenAI, "Learning to Reason with LLMs" (o1), 2024. URL: [https://openai.com/index/learning-to-reason-with-llms/](https://openai.com/index/learning-to-reason-with-llms/)

58. Guo, D., Yang, D., Zhang, H., et al., "DeepSeek-R1: Incentivizing Reasoning Capability in LLMs via Reinforcement Learning", arXiv:2501.12948, 2025. URL: [https://arxiv.org/abs/2501.12948](https://arxiv.org/abs/2501.12948)

### Retrieval-Augmented Generation

59. Lewis, P., Perez, E., Piktus, A., et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks", *Proc. NeurIPS*, 33, 2020. arXiv:2005.11401

### Efficient Training and Inference

60. Hu, E.J., Shen, Y., Wallis, P., Allen-Zhu, Z., Li, Y., Wang, S., Wang, L., Chen, W., "LoRA: Low-Rank Adaptation of Large Language Models", *Proc. ICLR*, 2022. arXiv:2106.09685

61. Dao, T., Fu, D.Y., Ermon, S., Rudra, A., Ré, C., "FlashAttention: Fast and Memory-Efficient Exact Attention with IO-Awareness", *NeurIPS*, 2022. arXiv:2205.14135

62. Dettmers, T., Lewis, M., Belkada, Y., Zettlemoyer, L., "GPTQ: Accurate Post-Training Quantization for Generative Pre-trained Transformers", *Proc. ICLR*, 2023. arXiv:2210.17323

63. Hinton, G.E., Vinyals, O., Dean, J., "Distilling the Knowledge in a Neural Network", arXiv:1503.02531, 2015. URL: [https://arxiv.org/abs/1503.02531](https://arxiv.org/abs/1503.02531)

### State Space Models

64. Gu, A., Dao, T., "Mamba: Linear-Time Sequence Modeling with Selective State Spaces", arXiv:2312.00752, 2023. URL: [https://arxiv.org/abs/2312.00752](https://arxiv.org/abs/2312.00752)

### Textbooks

65. Goodfellow, I., Bengio, Y., Courville, A., *Deep Learning*, MIT Press, 2016. ISBN: 978-0262035613. URL: [https://www.deeplearningbook.org/](https://www.deeplearningbook.org/)

66. Russell, S., Norvig, P., *Artificial Intelligence: A Modern Approach*, 4th ed., Pearson, 2020. ISBN: 978-0134610993. URL: [http://aima.cs.berkeley.edu/](http://aima.cs.berkeley.edu/)

67. Bishop, C.M., *Pattern Recognition and Machine Learning*, Springer, 2006. ISBN: 978-0387310732. URL: [https://www.springer.com/gp/book/9780387310732](https://www.springer.com/gp/book/9780387310732)

68. Mitchell, T., *Machine Learning*, McGraw-Hill, 1997. ISBN: 978-0070428072

69. Murphy, K.P., *Probabilistic Machine Learning: An Introduction*, MIT Press, 2022. ISBN: 978-0262046824. URL: [https://probml.github.io/pml-book/](https://probml.github.io/pml-book/)

70. Murphy, K.P., *Probabilistic Machine Learning: Advanced Topics*, MIT Press, 2023. ISBN: 978-0262048453. URL: [https://probml.github.io/pml-book/](https://probml.github.io/pml-book/)

71. Cover, T.M., Thomas, J.A., *Elements of Information Theory*, 2nd ed., Wiley, 2006. ISBN: 978-0471241959

72. Strang, G., *Introduction to Linear Algebra*, 5th ed., Wellesley-Cambridge Press, 2016. ISBN: 978-0980232776

73. Boyd, S., Vandenberghe, L., *Convex Optimization*, Cambridge University Press, 2004. ISBN: 978-0521833783. URL: [https://web.stanford.edu/~boyd/cvxbook/](https://web.stanford.edu/~boyd/cvxbook/)

74. Shannon, C.E., "A Mathematical Theory of Communication", *Bell System Technical Journal*, 27(3):379–423, 1948. DOI: [10.1002/j.1538-7305.1948.tb01338.x](https://doi.org/10.1002/j.1538-7305.1948.tb01338.x)

### Historical and Philosophical

75. Lighthill, J., "Artificial Intelligence: A General Survey", *Artificial Intelligence: A Paper Symposium*, Science Research Council, 1973.

76. McCorduck, P., *Machines Who Think: A Personal Inquiry into the History and Prospects of Artificial Intelligence*, 2nd ed., A.K. Peters, 2004. ISBN: 978-1568812052

77. Nilsson, N.J., *The Quest for Artificial Intelligence: A History of Ideas and Achievements*, Cambridge University Press, 2009. ISBN: 978-0521122930

### Additional Foundational References

78. Lecun, Y., Bottou, L., Orr, G.B., Müller, K.R., "Efficient BackProp", in *Neural Networks: Tricks of the Trade*, Springer, 1998. DOI: [10.1007/978-3-642-35289-8_3](https://doi.org/10.1007/978-3-642-35289-8_3)

79. Glorot, X., Bengio, Y., "Understanding the Difficulty of Training Deep Feedforward Neural Networks", *Proc. AISTATS*, 9:249–256, 2010.

80. Srivastava, N., Hinton, G.E., Krizhevsky, A., Sutskever, I., Salakhutdinov, R., "Dropout: A Simple Way to Prevent Neural Networks from Overfitting", *Journal of Machine Learning Research*, 15(1):1929–1958, 2014. URL: [https://jmlr.org/papers/v15/srivastava14a.html](https://jmlr.org/papers/v15/srivastava14a.html)

81. Ioffe, S., Szegedy, C., "Batch Normalization: Accelerating Deep Network Training by Reducing Internal Covariate Shift", *Proc. ICML*, 2015. arXiv:1502.03167

82. Kingma, D.P., Ba, J., "Adam: A Method for Stochastic Optimization", *Proc. ICLR*, 2015. arXiv:1412.6980

83. Pascanu, R., Mikolov, T., Bengio, Y., "On the Difficulty of Training Recurrent Neural Networks", *Proc. ICML*, 2013. arXiv:1211.5063

84. Fedus, W., Zoph, B., Shazeer, N., "Switch Transformers: Scaling to Trillion Parameter Models with Simple and Efficient Sparsity", *Proc. ICML*, 2022. arXiv:2101.03961

85. Radford, A., Wu, J., Child, R., Luan, D., Amodei, D., Sutskever, I., "Language Models are Unsupervised Multitask Learners", OpenAI, 2019. URL: [https://cdn.openai.com/better-language-models/language_models_are_unsupervised_multitask_learners.pdf](https://cdn.openai.com/better-language-models/language_models_are_unsupervised_multitask_learners.pdf)
## References

- Russell, S. & Norvig, P., "Artificial Intelligence: A Modern Approach," 4th Edition, Pearson, 2020.
- Goodfellow, I., Bengio, Y., & Courville, A., "Deep Learning," MIT Press, 2016. https://www.deeplearningbook.org/
- Vaswani, A. et al., "Attention Is All You Need," NeurIPS 2017. https://arxiv.org/abs/1706.03762
- LeCun, Y., Bengio, Y., & Hinton, G., "Deep Learning," Nature 521, 2015. https://doi.org/10.1038/nature14539
- Krizhevsky, A. et al., "ImageNet Classification with Deep Convolutional Neural Networks," NeurIPS 2012.
- Silver, D. et al., "Mastering the game of Go with deep neural networks," Nature 529, 2016.
- Brown, T. et al., "Language Models are Few-Shot Learners," NeurIPS 2020. https://arxiv.org/abs/2005.14165
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
- Mnih, V. et al., "Human-level control through deep reinforcement learning," Nature 518, 2015.
- Hochreiter, S. & Schmidhuber, J., "Long Short-Term Memory," NeurIPS 1997.
