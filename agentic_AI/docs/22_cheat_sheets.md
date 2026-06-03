# Complete AI/ML/DL & Agentic AI Cheat Sheets

> A quick-reference companion for the deep-researcher / agentic_AI repo.
> Every table is in a fenced code block so it renders correctly in any Markdown viewer.

---

## 1. Algorithm Selection Cheat Sheet

```
+----------------------------------+----------------------------------------------+--------------------------------+
| Problem Type                     | Best Algorithm(s)                            | When to Use                     |
+----------------------------------+----------------------------------------------+--------------------------------+
| Binary Classification           | Logistic Reg, XGBoost, SVM                   | Small data, need prob output    |
| Multi-class Classification      | Random Forest, XGBoost, Neural Net          | >10k samples, mixed features    |
| Regression (continuous)         | Linear Reg, XGBoost, LightGBM               | Tabular data, feature importance|
| Time-series Forecasting         | ARIMA, Prophet, TimesFM, PatchTST            | Seasonal data, long horizons   |
| Anomaly Detection               | Isolation Forest, Autoencoder, LOF          | Imbalanced, unlabeled dat a     |
| Clustering (unsupervised)       | K-Means, DBSCAN, HDBSCAN, Spectral          | Unknown group count → HDBSCAN  |
| Dimensionality Reduction        | PCA, UMAP, t-SNE, Autoencoder               | t-SNE for viz only, UMAP general|
| Recommender Systems             | Collaborative Filtering, NCF, Two-Tower     | Large sparse user-item matrix  |
| Ranking / Learning-to-Rank      | XGBoost-Rank, LambdaMART, SetTransformer    | Search, recommendation ranking |
| Graph Learning                  | GCN, GAT, GraphSAGE, GIN                    | Node/edge/graph-level pred      |
| Object Detection                | YOLOv8/v9/v10, DETR, Faster R-CNN           | Real-time → YOLO; accuracy →   |
|                                  |                                              | DETR w/ Deformable Attention    |
| Segmentation (semantic)         | U-Net, DeepLabV3+, Segment Anything (SAM)   | Medical → U-Net; general → SAM |
| Segmentation (instance)         | Mask R-CNN, Mask2Former, SAM                | COCO-style → Mask2Former       |
| Text Generation                 | Transformer (decoder), Mamba, RWKV          | Long context → Mamba/RWKV      |
| Machine Translation             | Transformer (enc-dec), mBART, NLLB           | Low-resource → NLLB-200        |
| Speech Recognition              | Whisper, Conformer, WavLM                    | Multilingual → Whisper large   |
| RL (discrete actions)           | PPO, DQN, Rainbow                            | On-policy → PPO; off-pol → DQN |
| RL (continuous actions)         | PPO, SAC, TD3                                | Robust exploration → SAC       |
| Image Generation                | Diffusion (SDXL, Flux), GAN (StyleGAN3)      | Diverse/high-qual → Diffusion  |
| Code Generation                 | LLM (CodeLlama, StarCoder2, DeepSeek-Coder) | Fill-in-middle → StarCoder2    |
| Retrieval-Augmented Gen (RAG)   | LLM + Vector DB (FAISS/Qdrant) + Retriever  | Knowledge-intensive, low Hallu.|
+----------------------------------+----------------------------------------------+--------------------------------+
```

---

## 2. Hyperparameter Quick Reference

```
+------------------------------+----------------------------+---------------------------+----------------------------+
| Model Family                | HP                         | Default / Starting Value  | Range / Notes              |
+------------------------------+----------------------------+---------------------------+----------------------------+
| CNN (ResNet)                 | learning_rate              | 1e-3                      | 1e-4 – 1e-2, cosine anneal |
| CNN (ResNet)                 | weight_decay               | 1e-4                      | 1e-5 – 1e-3                |
| CNN (ResNet)                 | batch_size                 | 256                       | 32 – 512 (GPU dependent)   |
| Transformer (enc-dec)        | d_model                    | 512                       | 256 / 512 / 768 / 1024     |
| Transformer (enc-dec)        | num_heads                  | 8                         | 4 / 8 / 16                 |
| Transformer (enc-dec)        | num_layers                 | 6                         | 2 – 24                     |
| Transformer (enc-dec)        | warmup_steps               | 4000                      | 1-10% of total steps       |
| GPT-2 style (124M)           | n_embd                     | 768                       | 768 / 1024 / 1280 / 1600  |
| GPT-2 style (124M)           | n_layer                    | 12                        | 12 / 24 / 36 / 48          |
| GPT-2 style (124M)           | n_head                     | 12                        | = n_embd / 64              |
| LLM (7B) fine-tune           | lr                         | 2e-5                      | 1e-5 – 5e-5 (FT); 1e-4 for |
|                              |                            |                           | LoRA                        |
| LLM (7B) fine-tune           | batch_size (eff.)          | 128 – 256                 | gradient accumulation       |
| LLM (7B) fine-tune           | max_seq_len                | 2048 – 4096               | 8192+ w/ RoPE scaling      |
| LoRA                         | lora_r                     | 8                         | 4 – 64 (higher = more cap.) |
| LoRA                         | lora_alpha                 | 16                        | 2× lora_r is common        |
| LoRA                         | lora_dropout               | 0.05                      | 0.0 – 0.1                  |
| QLoRA                        | lora_r                     | 64                        | Higher than LoRA (quant loss|
| QLoRA                        | quant_type                 | nf4                       | nf4 > fp4                   |
| QLoRA                        | compute_dtype              | bfloat16                  | bf16 on Ampere+, fp16 older |
| DPO                           | beta                       | 0.1                       | 0.05 – 0.5                 |
| DPO                           | lr                         | 5e-7                      | 1e-7 – 1e-6                |
| PPO (RLHF)                   | clip_range                 | 0.2                       | 0.1 – 0.3                  |
| PPO (RLHF)                   | kl_coef                    | 0.2                       | 0.01 – 0.5                 |
| Diffusion (SDXL)             | lr                         | 1e-4 (Unet)               | 1e-5 – 1e-4                |
| Diffusion (SDXL)             | ema_decay                  | 0.9999                    | 0.999 – 0.9999             |
| Diffusion (SDXL)             | noise_offset               | 0.1                       | 0 – 0.15                   |
+------------------------------+----------------------------+---------------------------+----------------------------+
```

---

## 3. Training Recipe Cheat Sheet

### CNN Training Recipe

```
┌─────────────────────────────────────────────────────────────────┐
│                     CNN TRAINING RECIPE                          │
├─────────────────────────────────────────────────────────────────┤
│ 1. Data: augment (RandomCrop, HFlip, ColorJitter, Mixup α=0.2) │
│ 2. Optim: AdamW  lr=1e-3  wd=1e-4  betas=(0.9, 0.999)         │
│ 3. Schedule: CosineAnnealingLR  T_max=epochs  eta_min=1e-6     │
│ 4. Warmup: LinearWarmup for 5 epochs                            │
│ 5. Regularization: LabelSmoothing ε=0.1, Dropout=0.2–0.5        │
│ 6. Precision: AMP (fp16/bf16) + torch.compile()                 │
│ 7. Epochs: 100–300 (early stop patience=20)                     │
│ 8. Eval: top-1 + top-5 accuracy, confusion matrix               │
└─────────────────────────────────────────────────────────────────┘
```

### Transformer / LLM Training Recipe

```
┌─────────────────────────────────────────────────────────────────┐
│                  TRANSFORMER / LLM TRAINING RECIPE              │
├─────────────────────────────────────────────────────────────────┤
│ Phase 1 — Pre-training                                          │
│   ┌───────────────────────────────────────────────────┐         │
│   │ Data: 1T–13T tokens, deduplicated, PII filtered   │         │
│   │ Model: Transformer-decoder, RoPE, SwiGLU, RMSNorm│         │
│   │ Optim: AdamW β=(0.9,0.95), lr=3e-4 → cosine decay│         │
│   │ BS: 4M tokens/grad-step (grad accum = 4M/(bs*seq))│         │
│   │ Warmup: 2000 steps → hold → cosine to 1e-5        │         │
│   │ Precision: bf16 + FlashAttention-2                 │         │
│   │ Parallelism: FSDP or 3D (TP+PP+DP)                │         │
│   │ Steps: 100k–1M+ depending on data size             │         │
│   └───────────────────────────────────────────────────┘         │
│ Phase 2 — SFT                                                   │
│   ┌───────────────────────────────────────────────────┐         │
│   │ Data: 10k–100k high-quality instruction pairs      │         │
│   │ lr: 2e-5, epochs: 3, pack sequences                │         │
│   │ Loss: ignore padding, mask response prefix         │         │
│   └───────────────────────────────────────────────────┘         │
│ Phase 3 — RLHF / DPO                                            │
│   ┌───────────────────────────────────────────────────┐         │
│   │ Reward model: 1 epoch on preference pairs          │         │
│   │ PPO: lr=1e-6, kl_coef=0.2, clip=0.2                │         │
│   │ OR: DPO β=0.1, lr=5e-7, 1 epoch                    │         │
│   └───────────────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Evaluation Metrics Cheat Sheet

```
+-------------------+-------------------------+----------------------------------------+---------------------------+
| Task              | Primary Metric(s)       | Secondary Metrics                      | Notes                     |
+-------------------+-------------------------+----------------------------------------+---------------------------+
| Classification    | Accuracy, F1            | Precision, Recall, AUC-ROC, MCC        | Imbalanced → F1/MCC       |
| Regression         | RMSE, MAE               | R², MedAE, MAPE                        | Outliers → MedAE          |
| Object Detection   | mAP@0.5, mAP@0.5:0.95  | Precision, Recall, FPS                 | COCO eval protocol        |
| Segmentation       | mIoU, Dice              | Pixel Acc, Boundary IoU, Boundary F1  | Medical → Dice           |
| Generation (NLG)   | BLEU, ROUGE-L           | BERTScore, COMET, chrF++               | MT → COMET; Summ → ROUGE |
| LLM Generation     | Perplexity              | MMLU, HumanEval, GPQA, MATH            | Use task-specific benches |
| Retrieval / RAG    | Recall@K, MRR, nDCG@K  | Hit Rate, Precision@K, EM             | K ∈ {1,5,10,20,100}      |
| Ranking            | NDCG@K, MAP@K           | MRR, Hit Rate                          | Graded rel → NDCG; binary |
|                   |                         |                                        | → MAP                     |
| RL                 | Avg Reward, Success Rate | Regret, Sample Efficiency              | Discount γ=0.99           |
| Speech (ASR)       | WER                     | CER, SER                               | CER for CJK languages    |
| Anomaly Detection  | AUROC, AUPRC            | F1@best-threshold, Avg Precision       | Imbalanced → AUPRC        |
| Embeddings         | Cosine Sim, MRR         | STS Pearson/Spearman                   | Sent-Bench for evaluation |
+-------------------+-------------------------+----------------------------------------+---------------------------+
```

---

## 5. Fine-tuning Decision Matrix

```
+------------------+------------+------------+-----------+----------+---------------+---------------+
| Method           | % Trainable| VRAM 7B    | Quality   | Speed    | Best For      | Libraries     |
+------------------+------------+------------+-----------+----------+---------------+---------------+
| Full Fine-Tune   | 100%       | ~60 GB     | ★★★★★    | ★★☆☆☆  | Max quality,  | HF Trainer     |
|                  |            | (bf16)     |           |          | ample compute | DeepSpeed     |
| LoRA             | ~0.5%      | ~16 GB     | ★★★★☆    | ★★★★☆  | Most use-cases| PEFT, LoRA+   |
|                  |            | (bf16)     |           |          | single-task   |               |
| QLoRA (nf4)     | ~0.5%      | ~10 GB     | ★★★★☆    | ★★★☆☆  | Consumer GPUs | bitsandbytes  |
|                  |            |            |           |          | 7B–13B models | AutoGPTQ      |
| IA³              | ~0.01%     | ~14 GB     | ★★★☆☆    | ★★★★★  | Extreme VRAM  | PEFT          |
|                  |            |            |           |          | constraints   |               |
| Prefix Tuning    | ~0.1%      | ~14 GB     | ★★★☆☆    | ★★★★☆  | Multi-task    | PEFT          |
|                  |            |            |           |          | w/ task prefixes              |
| Prompt Tuning     | ~0.01%     | ~13 GB     | ★★☆☆☆    | ★★★★★  | Quick protos, | PEFT          |
|                  |            |            |           |          | >10B models   |               |
+------------------+------------+------------+-----------+----------+---------------+---------------+

Decision Flow:
                        Need max quality?
                       /                \
                     Yes                 No
                      |                   |
                 Full FT             VRAM < 24 GB?
                                 /              \
                               Yes               No
                                |                 |
                            QLoRA              LoRA
                                |
                         Extreme VRAM constraint?
                        /              \
                      Yes               No
                       |                 |
                     IA³             Prefix Tuning?
                                     /          \
                                   Multi-task    Single-task
                                       |            |
                                  Prefix Tun      LoRA
```

---

## 6. Multi-Agent Architecture Selection Guide

```
+-----------------------+--------------------+--------------------+------------------+
| Pattern               | Description        | Best For           | Example Framework|
+-----------------------+--------------------+--------------------+------------------+
| Supervisor            | Single orchestrator | Simple pipelines,  | LangGraph,       |
|                       | dispatches tasks   | clear ownership    | AutoGen          |
| Hierarchical          | Multi-level managers| Complex projects,  | CrewAI,          |
|                       | / agents per level | specialized sub-   | LangGraph        |
|                       |                    | teams              |                  |
| Swarm / Round-Robin   | Agents hand off to  | Open-ended tasks,  | OpenAI Swarm,    |
|                       | next agent in loop | brainstorming      | AutoGen          |
| MapReduce Fan-out     | Parallel agents each| Summarization,     | LangGraph,       |
|                       | process a chunk,   | batch processing,  | custom           |
|                       | then reduce merges | code review        |                  |
| Blackboard / Shared   | Common memory board | Collaborative      | CrewAI,          |
| Memory                | all agents read/   | problem solving    | LangGraph        |
|                       | write              |                    |                  |
| Debate / Adversarial  | Two+ agents argue, | Red-teaming,       | AutoGen,         |
|                       | judge decides      | fact-checking,     | custom           |
|                       |                    | alignment          |                  |
| Reflection + Refine   | Agent generates,   | Writing, coding,   | Reflexion,       |
|                       | reviews, rewrites  | iterative improve  | LangGraph        |
| Tool-Use Only         | Single LLM calls   | Quick automations, | ReAct agents,    |
|                       | tools as needed    | RAG+tools          | LlamaIndex       |
+-----------------------+--------------------+--------------------+------------------+

Architecture Decision Tree:

                  How many agents?
                 /                \
               1                   2+
               |                   |
          ReAct / Tool-Use    Is the workflow
                              deterministic?
                             /              \
                           Yes               No
                            |                 |
                     Supervisor or         Need creativity?
                     Pipeline DAG         /              \
                                        Yes              No
                                         |                |
                                    Debate or          Hierarchical
                                    Swarm              or Blackboard
```

---

## 7. Tool Selection Matrix

```
+----------------------+----------------------------+----------------------------+--------------------------+
| Layer                | Tool                       | Alternative                | Notes                    |
+----------------------+----------------------------+----------------------------+--------------------------+
| Training Framework   | PyTorch 2.x               | JAX + Flax, PaddlePaddle   | torch.compile() + FSDP   |
| Distributed Training | FSDP + torchrun            | DeepSpeed ZeRO-3, Ray Train | FSDP native PyTorch      |
| LLM Pre-training     | Megatron-LM               | LitGPT, torchtitan          | 3D parallelism built-in  |
| Fine-tuning (SFT)     | HF Trainer + TRL           | LLaMA-Factory, Axolotl      | TRL for DPO/PPO          |
| PEFT                  | bitsandbytes + PEFT        | LoRA+, DoRA, Apollo         | QLoRA best for ≤24 GB    |
| Data Processing       | datasets + tokenizer       | chonkie, datatrove          | chonkie for chunking     |
| Evaluation           | lm-eval-harness (HF)       | HELM, Open LLM Leaderboard | lm-eval most widely used |
| Serving (inference)   | vLLM                        | TGI, TensorRT-LLM, TRT-LLM  | vLLM: PagedAttention     |
| Serving (edge)        | llama.cpp, MLC-LLM         | GGML, CoreML, ONNX Runtime  | quantized GGUF format    |
| Vector DB             | Qdrant / Weaviate          | Milvus, Pinecone, Chroma    | Qdrant: open-source, fast|
| Orchestration         | LangGraph                   | CrewAI, AutoGen, Haystack   | LangGraph: graph-based   |
| Observability         | LangSmith, Phoenix (Arize) | Helicone, Dynatrace         | Phoenix: open-source     |
| RAG Frameworks        | LlamaIndex                  | Haystack, LangChain          | LlamaIndex: data-focused |
| Container / Infra     | Kubernetes + Helm           | Docker Compose, Ray          | K8s for prod scale      |
| Experiment Tracking   | Weights & Biases            | MLflow, ClearML, Neptune     | W&B: visual dashboards   |
+----------------------+----------------------------+----------------------------+--------------------------+
```

---

## 8. Common Error Patterns and Solutions

```
+----------------------------------+----------------------------------------------+-------------------------------------------+
| Error / Symptom                  | Root Cause                                  | Fix                                       |
+----------------------------------+----------------------------------------------+-------------------------------------------+
| Loss spikes mid-training        | LR too high, bad batch, gradient explosion  | Gradient clipping (norm 1.0), lower LR,   |
|                                  |                                              | increase warmup, check data for outliers  |
| Loss = NaN                       | Numerical overflow / underflow              | bf16 instead of fp16, lower LR, add       |
|                                  |                                              | epsilon to denom, check for zero-length seq|
| OOM during training             | Batch size / seq_len too large              | Gradient accumulation, FSDP, FlashAttn-2, |
|                                  |                                              | DeepSpeed ZeRO-3                          |
| Model generates repeated text   | Repetition penalty missing, temp too low    | repetition_penalty=1.1–1.3, top_p=0.9,    |
|                                  |                                              | increase temperature                     |
| Hallucinations in RAG            | Retriever returns irrelevant docs            | Improve chunking, hybrid search (dense+  |
|                                  |                                              | sparse), reranking, increase top-k        |
| LoRA / adapter has no effect     | Learning rate too low or wrong target modules| Target ALL linear layers (not just attn), |
|                                  |                                              | increase lora_r to 16–32                  |
| Fine-tune destroys chat ability | Overfitting on small SFT data                | Mix with general chat data (5-10%), lower |
|                                  |                                              | LR, train for fewer epochs               |
|梯度accum not matching single-GPU | Loss normalize wrong                        | Divide loss by accum_steps or set         |
|                                  |                                              | gradient_accumulation_steps in Trainer    |
| DPO loss goes negative          | Reference model too different from policy    | Lower DPO β (0.05), ensure ref model is   |
|                                  |                                              | the pre-FT checkpoint                    |
| Distributed training deadlock   | NCCL timeout, uneven data                   | Set NCCL_TIMEOUT=1800, ensure all ranks   |
|                                  |                                              | see equal batches, check CUDA devices    |
| Slow inference                   | No KV-cache, no PagedAttention               | Use vLLM / TGI, enable KV-cache, batch   |
|                                  |                                              | requests, consider speculative decoding  |
+----------------------------------+----------------------------------------------+-------------------------------------------+
```

---

## 9. GPU / Compute Selection Guide

```
+----------------+----------+-----------+------------+------------------+----------------------------+
| GPU            | VRAM     | FP16 TFLOPS| $/hr (cloud)| Multi-GPU Link   | Recommended Workload       |
+----------------+----------+-----------+------------+------------------+----------------------------+
| RTX 3060 12GB  | 12 GB    | ~25       | ~$0.20     | —                 | QLoRA 7B, SFT <2B, RAG inf |
| RTX 3090 24GB  | 24 GB    | ~71       | ~$0.35     | —                 | LoRA 7B–13B, QLoRA 34B    |
| RTX 4090 24GB  | 24 GB    | ~165      | ~$0.65     | —                 | LoRA 13B, QLoRA 70B, inf  |
| A100 40GB     | 40 GB    | ~312      | ~$2.50     | NVLink 600 GB/s   | Full FT 7B, LoRA 70B      |
| A100 80GB     | 80 GB    | ~312      | ~$3.50     | NVLink 600 GB/s   | Full FT 13B, LoRA 70B+    |
| H100 80GB     | 80 GB    | ~990      | ~$4.50     | NVLink 900 GB/s   | Pre-train, Full FT 30B+   |
| H200 141GB    | 141 GB   | ~990      | ~$5.50     | NVLink 900 GB/s   | Pre-train 70B+, Full FT   |
| T4 16GB       | 16 GB    | ~65 (FP16)| ~$0.35     | —                 | Inference only, batch inf |
| A10G 24GB     | 24 GB    | ~125      | ~$1.00     | —                 | LoRA 7B–13B, serving      |
| MI300X 192GB  | 192 GB   | ~1,300    | ~$5.00     | Infinity Fabric   | Large-scale training      |
+----------------+----------+-----------+------------+------------------+----------------------------+

Quick VRAM Estimation:
  ┌─────────────────────────────────────────────────────────┐
  │ Parameter Count × bytes_per_param × (1 + overhead)      │
  │                                                         │
  │ FP32: 4 bytes/param   BF16/FP16: 2 bytes/param          │
  │ INT8: 1 byte/param    INT4/NF4: 0.5 bytes/param         │
  │                                                         │
  │ Overhead ≈ 20-30% (optimizer states, activations, grads)│
  │                                                         │
  │ Example: 7B model BF16 full-FT                          │
  │   7B × 2B × 1.3 ≈ 18.2 GB + optimizer ≈ 42 GB          │
  │ Example: 7B model QLoRA (nf4)                           │
  │   7B × 0.5B × 1.3 ≈ 4.5 GB + LoRA ≈ 8 GB               │
  └─────────────────────────────────────────────────────────┘
```

---

## 10. Token / Cost Estimation Guide

### OpenAI API Pricing (as of 2025)

```
+---------------------------+----------------+----------------+--------------------+
| Model                     | Input / 1M tok | Output / 1M tok| Notes               |
+---------------------------+----------------+----------------+--------------------+
| GPT-4o                    | $2.50          | $10.00         | Best quality/cost  |
| GPT-4o-mini               | $0.15          | $0.60          | Fast, cheap        |
| GPT-4 Turbo                | $10.00         | $30.00         | Legacy, 128k ctx   |
| o1-preview                 | $15.00         | $60.00         | Reasoning model    |
| o1-mini                    | $3.00          | $12.00         | Lighter reasoning  |
| o3-mini                    | $1.10          | $4.40          | Cost-effective reas.|
| Claude 3.5 Sonnet (API)    | $3.00          | $15.00         | Anthropic          |
| Claude 3.5 Haiku (API)     | $0.80          | $4.00          | Anthropic, fast    |
| Gemini 1.5 Pro             | $1.25          | $5.00          | Google, 1M+ ctx   |
| Gemini 1.5 Flash           | $0.075         | $0.30          | Google, cheap      |
+---------------------------+----------------+----------------+--------------------+
```

### Cost Estimation Formula

```
┌──────────────────────────────────────────────────────────────────────┐
|                                                                      |
|  Total Cost = (input_tokens × input_price) + (output_tokens ×       |
|               output_price)                                          |
|                                                                      |
|  Tokens ≈ characters / 4  (English)                                 |
|  Tokens ≈ characters / 2  (CJK languages)                           |
|                                                                      |
|  Example: Summarize 10 docs × 8k tokens each                        |
|    Input:  80,000 × ($2.50 / 1M) = $0.20                            |
|    Output: 10 × 500 = 5,000 × ($10.00 / 1M) = $0.05                 |
|    Total = $0.25                                                     |
|                                                                      |
|  Self-hosted GPU cost estimation:                                    |
|    Cost = hours × $/hr                                               |
|    Hours ≈ (tokens × FLOPs/param) / (GPU_FLOPs × utilization 0.5)   |
|                                                                      |
|  Example: LLaMA-7B, 1B tokens, A100 80GB ($3.50/hr)                  |
|    FLOPs ≈ 6 × 7B × 1B = 42 TFLOPs-seconds / (312 TF × 0.5)        |
|    ≈ 0.27M sec ≈ 75 hours                                           |
|    Cost ≈ 75 × $3.50 ≈ $262.50                                      |
|                                                                      |
└──────────────────────────────────────────────────────────────────────┘
```

---

## 11. Prompt Engineering Patterns for Agents

```
+------------------+------------------------------------------+----------------------------------------------+
| Pattern          | Description                              | Template                                     |
+------------------+------------------------------------------+----------------------------------------------+
| ReAct            | Reason then Act in a loop                | Thought: [reason about observation]          |
|                  |                                          | Action: [tool_name(input)]                   |
|                  |                                          | Observation: [tool output]                   |
|                  |                                          | ... repeat until Answer:                     |
| Chain-of-Thought | Step-by-step reasoning before answer      | Let's think step by step.                    |
|                  |                                          | 1. First, ...                               |
|                  |                                          | 2. Then, ...                                 |
|                  |                                          | Therefore, the answer is...                 |
| Few-Shot         | Provide k examples before the query       | Example 1: input → output                   |
|                  |                                          | Example 2: input → output                   |
|                  |                                          | Now: {query} →                               |
| Self-Ask         | Agent asks follow-up questions           | Question: {original}                         |
|                  |                                          | Follow up: {sub-question}                   |
|                  |                                          | Intermediate answer: {answer}                |
|                  |                                          | So the final answer is:                      |
| Reflection        | Generate → critique → revise             | Draft: {initial_response}                   |
|                  |                                          | Critique: what could be improved? ...        |
|                  |                                          | Revised: {improved_response}                 |
| Tool-Augmented   | LLM chooses from a tool palette          | Available tools: {tool_descriptions}         |
|                  |                                          | User query: {query}                          |
|                  |                                          | Select tool and arguments:                   |
| Routing           | Classify query, route to specialist       | Categorize the query into: {categories}      |
|                  |                                          | Query: {query}                               |
|                  |                                          | Category: [classification]                   |
|                  |                                          | Route to: {specialist_agent}                 |
| Plan-and-Solve   | Decompose into plan, then execute        | Plan:                                        |
|                  |                                          |  Step 1: {subtask_1}                         |
|                  |                                          |  Step 2: {subtask_2}                         |
|                  |                                          | Execute each step...                         |
| Persona           | Adopt a role/expertise                    | You are a {role} with expertise in {domain}. |
|                  |                                          | {task_instructions}                          |
| Structured Output| Enforce JSON/schema output                | Respond in the following JSON schema:        |
|                  |                                          | {json_schema}                                |
|                  |                                          | Input: {query}                               |
+------------------+------------------------------------------+----------------------------------------------+
```

---

## 12. Deployment Architecture Decision Guide

### Decision Tree

```
                         What is the deployment target?
                        /                |                \
                  Cloud API        Self-Hosted        Edge / On-Device
                      |                  |                     |
            Scale needed?          Latency?              Model size?
           /          \           /        \            /          \
        Low          High       Low       High       <1B          >1B
         |             |         |          |          |            |
     Serverless   Kubernetes  vLLM/Ollama  Triton    ONNX/TF-Lite TFLite/
     (Lambda/CF)  + vLLM/TGI  single-GPU   + TensorRT  CoreML      GGUF/
                  + autoscale             multi-GPU    Inference    llama.cpp
                               + batching   Server

```

### Architecture Comparison

```
+---------------------+------------------+------------------+------------------+------------------+
| Aspect              | Serverless API   | K8s + vLLM       | Triton Inference | Edge / On-Device |
+---------------------+------------------+------------------+------------------+------------------+
| Cold start          | 1-10s            | <1s (warm pods)  | <1s              | 0s               |
| Max throughput      | Provider-limited | High (batching)  | Very High        | Low              |
| Latency (TTFT)      | 200-500ms        | 50-200ms         | 10-50ms (small)  | 10-100ms         |
| Cost model          | Per-token        | Per-GPU-hour     | Per-GPU-hour     | Free (device)    |
| Model size          | Provider models  | Any (VRAM limit) | Any (GPU limits) | <7B quantized   |
| Multi-model         | Yes (API routes) | Yes (multiple    | Yes (ensembles)  | Usually 1        |
|                     |                  |  deployments)    |                  |                  |
| Autoscaling         | Built-in         | HPA + KEDA       | Triton dynamic   | N/A              |
|                     |                  |                  | batching         |                  |
| Observability       | Provider logs    | Prometheus +     | Triton metrics + | Device metrics   |
|                     |                  | Grafana          | Prometheus       |                  |
| Data privacy        | Data sent to     | Data stays in    | Data stays in    | Data on device   |
|                     | provider         | your VPC         | your VPC         |                  |
| Recommended for     | Prototyping,     | Production SaaS, | High-throughput  | Mobile, IoT,     |
|                     | low volume       | enterprise       | API endpoints    | offline use      |
+---------------------+------------------+------------------+------------------+------------------+
```

### Batched Serving Decision

```
  Need real-time responses?
 /                         \
Yes                         No
 |                           |
 vLLM continuous batching    Batch offline (spark/batch)
 with PagedAttention         + vLLM offline or HF pipeline
 |                           |
 SLA < 200ms TTFT?           Throughput priority
 |                           |
 Speculative decoding        Increase batch size
 (small draft model)          to max GPU utilization
```

---

## 13. Real References

### Foundational Papers

```
+-------------------------------------------+----------------------------------------------+
| Title                                     | Reference                                    |
+-------------------------------------------+----------------------------------------------+
| Attention Is All You Need                | Vaswani et al., 2017 — arXiv:1706.03762      |
| BERT: Pre-training of Deep Bidirectional | Devlin et al., 2019 — arXiv:1810.04805       |
| Transformers                              |                                              |
| Language Models are Few-Shot Learners     | Brown et al. (GPT-3), 2020 — arXiv:2005.14165|
| LoRA: Low-Rank Adaptation                | Hu et al., 2021 — arXiv:2106.09685            |
| QLoRA: Efficient Finetuning              | Dettmers et al., 2023 — arXiv:2305.14314      |
| Training language models to follow        | Ouyang et al. (InstructGPT), 2022 —           |
| instructions with human feedback         | arXiv:2203.02155                              |
| Direct Preference Optimization            | Rafailov et al., 2023 — arXiv:2305.18290      |
| FlashAttention-2                          | Dao, 2023 — arXiv:2307.08691                  |
| Mamba: Linear-Time Seq Modeling           | Gu & Dao, 2023 — arXiv:2312.00752             |
| ReAct: Synergizing Reasoning & Acting    | Yao et al., 2023 — arXiv:2210.03629           |
| Reflexion: Language Agents with Verbal    | Shinn et al., 2023 — arXiv:2303.11366         |
| Reinforcement Learning                    |                                              |
| Toolformer: Language Models as Tool Users | Schick et al., 2023 — arXiv:2302.04761        |
| Chain-of-Thought Prompting                | Wei et al., 2022 — arXiv:2201.11903           |
| LLaMA: Open Foundation Models             | Touvron et al., 2023 — arXiv:2302.13971       |
| Llama 2: Open Foundation & Fine-Tuned    | Touvron et al., 2023 — arXiv:2307.09288       |
| Chat Models                                |                                              |
| DeepSeek-V2: Strong, Economical, Efficient| DeepSeek, 2024 — arXiv:2405.04434             |
| Mixture-of-Experts                        |                                              |
| vLLM: Efficient Memory Management for     | Kwon et al., 2023 — arXiv:2309.06180          |
| LLM Serving                               |                                              |
+-------------------------------------------+----------------------------------------------+
```

### Books

```
+-------------------------------------------+----------------------------------------------+
| Title                                     | ISBN / Reference                             |
+-------------------------------------------+----------------------------------------------+
| Deep Learning                             | Goodfellow, Bengio & Courville — ISBN         |
|                                           | 978-0-262-03561-3                            |
| Dive into Deep Learning                   | Zhang et al. — ISBN 978-0-262-04844-6         |
|                                           | (free: d2l.ai)                               |
| Designing Machine Learning Systems        | Huyen, 2022 — ISBN 978-1-098-10795-3         |
| Transformers for NLP (2nd Ed.)            | Tunstall, von Werra & Wolf — ISBN            |
|                                           | 978-1-098-13648-2                            |
| Build a Large Language Model (From Scratch| 978-1-63735-022-9 (Manning MEAP)             |
| Hands-On Machine Learning (3rd Ed.)       | Géron, 2022 — ISBN 978-1-098-12597-4         |
+-------------------------------------------+----------------------------------------------+
```

### Documentation & Repos

```
+-------------------------------------------+----------------------------------------------+
| Resource                                  | URL                                          |
+-------------------------------------------+----------------------------------------------+
| PyTorch Documentation                     | https://pytorch.org/docs/stable/             |
| Hugging Face Transformers                 | https://huggingface.co/docs/transformers     |
| Hugging Face PEFT                         | https://huggingface.co/docs/peft             |
| Hugging Face TRL                          | https://huggingface.co/docs/trl              |
| bitsandbytes                              | https://github.com/TimDettmers/bitsandbytes  |
| vLLM                                      | https://github.com/vllm-project/vllm         |
| LangGraph                                 | https://langchain-ai.github.io/langgraph/     |
| LlamaIndex                                | https://docs.llamaindex.ai/                  |
| DeepSpeed                                 | https://github.com/microsoft/DeepSpeed        |
| Open LLM Leaderboard                      | https://huggingface.co/spaces/open-llm-leaderboard/open_llm_leaderboard      |
|                                           | leaderboard/open_llm_leaderboard             |
| LM Evaluation Harness                    | https://github.com/EleutherAI/lm-evaluation-harness  |
|                                           | harness                                      |
| Qdrant Vector DB                          | https://qdrant.tech/documentation/            |
| CrewAI                                    | https://docs.crewai.com/                     |
| AutoGen                                   | https://microsoft.github.io/autogen/         |
+-------------------------------------------+----------------------------------------------+
```

---

*Last updated: 2025..star*
## References

- Vaswani, A. et al., "Attention Is All You Need," NeurIPS 2017. https://arxiv.org/abs/1706.03762
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
- Yao, S. et al., "ReAct: Synergizing Reasoning and Acting in Language Models," ICLR 2023. https://arxiv.org/abs/2210.03629
- Lewis, P. et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks," NeurIPS 2020. https://arxiv.org/abs/2005.11401
- Hu, E.J. et al., "LoRA: Low-Rank Adaptation of Large Language Models," ICLR 2022. https://arxiv.org/abs/2106.09685
- LangChain Documentation. https://docs.langchain.com/
- LangGraph Documentation. https://langchain-ai.github.io/langgraph/
- OpenAI API Documentation. https://platform.openai.com/docs
- Anthropic Documentation. https://docs.anthropic.com
- Hugging Face Transformers. https://huggingface.co/docs/transformers/
- Kingma, D.P. & Ba, J., "Adam: A Method for Stochastic Optimization," ICLR 2015. https://arxiv.org/abs/1412.6980
- Schulman, J. et al., "Proximal Policy Optimization Algorithms," 2017. https://arxiv.org/abs/1707.06347
