# Model Deployment & MLOps Infrastructure

> A comprehensive guide to deploying, serving, scaling, and maintaining ML models in production—covering architectures, frameworks, optimization, orchestration, CI/CD, monitoring, and cost governance.

---

## Table of Contents

1. [Model Serving Architectures](#1-model-serving-architectures)
2. [Serving Frameworks](#2-serving-frameworks)
3. [Quantization Techniques](#3-quantization-techniques)
4. [Model Optimization](#4-model-optimization)
5. [Containerization & Orchestration](#5-containerization--orchestration)
6. [CI/CD for ML](#6-cicd-for-ml)
7. [Monitoring & Observability](#7-monitoring--observability)
8. [Auto-Scaling Strategies](#8-auto-scaling-strategies)
9. [A/B Testing & Canary Deployments](#9-ab-testing--canary-deployments)
10. [Cost Optimization](#10-cost-optimization)
11. [Security](#11-security)

---

## Full Deployment Architecture — End-to-End

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        FULL ML DEPLOYMENT ARCHITECTURE                         │
│                                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────────┐   │
│  │ Training │───>│   Model      │───>│  Artifact    │───>│  Optimization  │   │
│  │ Pipeline │    │  Registry    │    │  Repository   │    │  & Conversion   │   │
│  └──────────┘    └──────────────┘    └──────────────┘    └───────┬────────┘   │
│                                                                    │            │
│         ┌──────────────────────────────────────────────────────────┘            │
│         │                                                                       │
│         ▼                                                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Container   │───>│   Registry   │───>│ Kubernetes   │───>│   Serving     │  │
│  │   Build      │    │  (Harbor/    │    │  Cluster     │    │  Endpoints    │  │
│  │  (Docker)    │    │   ECR/GCR)   │    │              │    │  (vLLM/TGI/  │  │
│  └──────────────┘    └──────────────┘    └──────┬───────┘    │   Triton)    │  │
│                                                  │            └──────┬───────┘  │
│                                                  │                   │          │
│                                         ┌────────┴──────┐    ┌──────┴───────┐  │
│                                         │  Ingress /    │    │  Monitoring  │  │
│                                         │  API Gateway  │    │  & Logging   │  │
│                                         │  (Istio/Envoy)│    │ (Prometheus/ │  │
│                                         └───────────────┘    │  Grafana)    │  │
│                                                              └──────────────┘  │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                     FEEDBACK LOOP (Data → Retraining)                     │  │
│  │  ┌────────────┐    ┌──────────────┐    ┌──────────────┐                 │  │
│  │  │  Feature   │───>│   Drift      │───>│  Retraining  │                 │  │
│  │  │   Store    │    │  Detection   │    │  Trigger     │                 │  │
│  │  └────────────┘    └──────────────┘    └──────────────┘                 │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Model Serving Architectures

### 1.1 Architecture Comparison Matrix

| Architecture | Latency | Throughput | Cost | Complexity | Use Case |
|---|---|---|---|---|---|
| **Batch** | Minutes–Hours | Very High | Low | Low | Nightly scoring, report generation |
| **Real-Time** (sync) | 10–200 ms | Medium | High | Medium | Search ranking, fraud detection |
| **Streaming** | 100 ms–1 s | High | Medium | High | Transaction monitoring, log analysis |
| **Edge** | 1–50 ms | Low | Medium | High | Autonomous vehicles, IoT inference |

### 1.2 Batch Serving

Pre-compute predictions on a schedule. Entire datasets flow through the model offline; results are written to a feature store or data warehouse for downstream consumption.

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐      ┌────────────┐
│   Data       │─────>│   Batch      │─────>│  Model      │─────>│  Feature   │
│   Lake       │      │   Job        │      │  Inference  │      │  Store /  │
│  (S3/BigQuery│      │  (Spark/     │      │  Engine     │      │  Warehouse │
│   /Delta)    │      │   Airflow)   │      │             │      │            │
└─────────────┘      └──────────────┘      └─────────────┘      └────────────┘
```

**Key considerations:**
- Schedule via Airflow / Prefect / Dagster DAGs with idempotent task design.
- Use Spark MLlib or Ray Data for distributed inference across clusters.
- Write outputs partitioned by date (`output_date=YYYY-MM-DD/`) for downstream join ergonomics.
- Set `max_retries=3` with exponential backoff; checkpoint intermediate outputs to avoid full re-runs on failure.

### 1.3 Real-Time (Synchronous) Serving

Client sends a request, blocks until the model returns a prediction. This is the dominant pattern for user-facing features.

```
┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐
│  Client   │───>│  API Gateway │───>│  Model       │───>│  Response │
│  (HTTP/   │    │  (rate limit,│    │  Server      │    │  <50ms    │
│   gRPC)   │    │   auth)      │    │  (vLLM/TGI) │    │          │
└──────────┘    └──────────────┘    └──────────────┘    └──────────┘
```

**SLA targets by domain:**

| Domain | P50 | P99 | P99.9 |
|---|---|---|---|
| Search ranking | <20 ms | <80 ms | <200 ms |
| Fraud detection | <50 ms | <150 ms | <500 ms |
| LLM chat completion | <200 ms TTFT | <2 s TTFT | <5 s TTFT |
| Recommendation | <100 ms | <300 ms | <800 ms |

### 1.4 Streaming Serving

Continuous inference over unbounded data streams. Models consume from Kafka / Kinesis / Pulsar topics and emit predictions to downstream topics.

```
┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────┐    ┌──────────┐
│  Source   │───>│  Kafka   │───>│  Stream      │───>│  Model   │───>│  Sink    │
│  (logs,  │    │  Topic   │    │  Processor   │    │  Serve   │    │  (Kafka/ │
│  events) │    │          │    │  (Flink/     │    │  (batch) │    │  DB)     │
└──────────┘    └──────────┘    │   Bytewax)   │    └──────────┘    └──────────┘
                                └──────────────┘
```

**Best practices:**
- Use consumer group rebalancing for fault tolerance; process records at least-once with idempotent sinks.
- Set `max.poll.interval.ms` > than worst-case batch inference time to avoid re-balancing storms.
- Enable exactly-once semantics with Kafka transactions when writing predictions back to topics.
- Back-pressure: drop or buffer records when `inference_queue_depth > threshold` rather than crashing.

### 1.5 Edge Serving

Model runs directly on-device or on an edge node co-located with data generation.

```
┌─────────────────────────────────────────────────────────┐
│                    EDGE DEPLOYMENT                       │
│                                                          │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Sensor /  │───>│  Edge        │───>│  Optimized   │  │
│  │ Camera /  │    │  Runtime     │    │  Model       │  │
│  │ IoT Data │    │  (ONNX/TF-   │    │  (quantized  │  │
│  │           │    │   Lite/TFLite│    │   INT8/INT4) │  │
│  └──────────┘    └──────┬───────┘    └──────┬───────┘  │
│                         │                   │          │
│                         ▼                   ▼          │
│                 ┌──────────────┐   ┌──────────────┐    │
│                 │  Local       │   │  Cloud       │    │
│                 │  Decision    │   │  Sync (WiFi/ │    │
│                 │  (<5ms)      │   │   4G/5G)     │    │
│                 └──────────────┘   └──────────────┘    │
└─────────────────────────────────────────────────────────┘
```

**Tooling by platform:**

| Platform | Runtime | Format | Notes |
|---|---|---|---|
| NVIDIA Jetson | TensorRT | ONNX → TensorRT | Best perf for NVIDIA SoC |
| Raspberry Pi | ONNX Runtime / TFLite | TFLite / ONNX | Limited to ≤2B param models |
| iOS / macOS | Core ML | `.mlpackage` / `.mlmodelc` | Use `coremltools` to convert |
| Android | TFLite / NNAPI | `.tflite` | GPU delegate for NNAPI |
| Web browser | ONNX Runtime Web | ONNX | WebGL/WebGPU backends |

---

## 2. Serving Frameworks

### 2.1 Framework Decision Matrix

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     SERVING FRAMEWORK DECISION TREE                      │
│                                                                          │
│                        What are you serving?                             │
│                             │                                            │
│              ┌──────────────┼──────────────────┐                         │
│              ▼              ▼                  ▼                         │
│           LLM (gen)    Classic ML        Vision/Audio                    │
│              │              │                  │                         │
│     ┌────────┴──────┐  ┌───┴────┐        ┌───┴────┐                     │
│     │ Need PagedAtt?│  │ Single │        │ Need   │                     │
│     │               │  │ model  │        │ batching?│                    │
│     ├─YES──┬─NO──┐  │  │ only?  │        └───┬────┘                     │
│     ▼      ▼     ▼  │  ├──YES──┤            │                          │
│   vLLM  TensorRT  │  │  ▼     │    ┌───────┴───────┐                   │
│          -LLM  TGI │  │FastAPI │    │  Triton       │                   │
│     │      │     │  │TorchServe│   │  Inference     │                   │
│     │      │   Cloud│  │       │    │  Server        │                   │
│     │      │   only│  └───NO──┘    └───────┬───────┘                   │
│     │      │     │  ┌───┴────┐             │                            │
│     │      │     └─>│ Triton │◄────────────┘                            │
│     │      │        └────────┘                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 vLLM — Large Language Model Serving

vLLM implements **PagedAttention**, managing KV-cache memory as virtual pages to eliminate fragmentation and support ~2-4× more concurrent requests than naive HuggingFace serving.

```python
# vLLM offline batch inference
from vllm import LLM, SamplingParams

llm = LLM(
    model="meta-llama/Llama-3.1-70B-Instruct",
    tensor_parallel_size=4,        # Shard across 4 GPUs
    quantization="awq",            # Use AWQ quantized weights
    max_model_len=8192,
    gpu_memory_utilization=0.90,   # Reserve 10% for non-KV allocations
    enforce_eager=True,            # Disable CUDA graphs for debugging
)

sampling_params = SamplingParams(
    temperature=0.7,
    top_p=0.9,
    max_tokens=512,
    repetition_penalty=1.1,
)

outputs = llm.generate(prompts, sampling_params)
```

```bash
# vLLM OpenAI-compatible API server
python -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Llama-3.1-70B-Instruct \
    --tensor-parallel-size 4 \
    --max-model-len 8192 \
    --quantization awq \
    --port 8000 \
    --enable-chunked-prefill
```

**Production tuning knobs:**

| Parameter | Default | Tuning Guidance |
|---|---|---|
| `gpu_memory_utilization` | 0.9 | Raise to 0.95–0.98 on A100/H100; lower on consumer GPUs |
| `max_num_seqs` | 256 | Set to match expected concurrency; lower = less memory |
| `block_size` | 16 | Keep at 16 for most workloads; 8 for very short sequences |
| `swap_space` | 4 GB | Increase if seeing OOM during burst traffic |
| `enable_chunked_prefill` | False | Enable for heterogeneous request lengths |

### 2.3 TensorRT-LLM

NVIDIA's high-performance serving backend optimized for NVIDIA GPUs. Compiles model graphs into TensorRT engines with kernel fusion, weight-only quantization, and in-flight batching.

```python
# TensorRT-LLM model definition (simplified)
import tensorrt_llm
from tensorrt_llm import Tensor, str_dtype_to_trt

builder = tensorrt_llm.Builder()
builder.create_network()
builder_config = builder.create_builder_config(
    name="llama-70b",
    precision=str_dtype_to_trt("float16"),
)

# Enable FP8 quantization for GEMM layers
builder_config.set_quantization_flag(
    tensorrt_llm.quantization.FP8_FORMAT_E4M3
)

# Build engine with TP=4
engine = builder.build_engine(
    model=model,
    builder_config=builder_config,
    tensor_parallel=4,
)
```

**When to choose TensorRT-LLM over vLLM:**
- Yourequire maximum throughput on NVIDIA hardware and can tolerate longer engine build times (~30–60 min).
- You need FP8/INT8 weight-only quantization with NVIDIA custom kernels.
- You are deploying on DGX/H100 clusters and want NKOTB (next-gen) kernel autotuning.

### 2.4 Text Generation Inference (TGI)

HuggingFace's production server with continuous batching, flash attention, and quantization support baked in.

```bash
docker run --gpus all -p 8080:80 \
    -v $PWD/data:/data \
    ghcr.io/huggingface/text-generation-inference:2.1 \
    --model-id meta-llama/Llama-3.1-70B-Instruct \
    --sharded true \
    --num-shard 4 \
    --quantize awq \
    --max-input-length 2048 \
    --max-total-tokens 4096 \
    --max-batch-prefill-tokens 4096
```

### 2.5 Triton Inference Server

Multi-framework, multi-model production server supporting ensemble pipelines and dynamic batching.

```protobuf
# config.pbtxt — model configuration
name: "resnet50_classifier"
platform: "onnxruntime_onnx"
max_batch_size: 32

dynamic_batching {
  max_queue_delay_microseconds: 50000
  preferred_batch_size: [8, 16, 32]
}

instance_group [
  { count: 2 kind: KIND_GPU gpu: 0 },
  { count: 1 kind: KIND_CPU }
]

optimization {
  execution_accelerators {
    gpu_execution_accelerator [
      { name: "tensorrt" }
    ]
  }
}

input [
  { name: "input" data_type: TYPE_FP32 dims: [3, 224, 224] }
]
output [
  { name: "output" data_type: TYPE_FP32 dims: [1000] }
]
```

### 2.6 TorchServe

PyTorch-native serving with multi-model management, snapshot-based config, and metrics emission.

```bash
torchserve --start \
    --model-store /models \
    --models all \
    --ts-config config.properties
```

```properties
# config.properties
inference_address=http://0.0.0.0:8080
management_address=http://0.0.0.0:8081
metrics_address=http://0.0.0.0:8082
default_workers_per_model=4
job_queue_size=100
max_response_size=6553500
max_request_size=6553500
enable_metrics_api=true
install_py_dep_per_model=true
```

### 2.7 FastAPI — Lightweight Custom Serving

When you need full control over pre/post-processing logic, business rules, or non-standard inference flows.

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import asyncio
from concurrent.futures import ThreadPoolExecutor

app = FastAPI(title="Sentiment API", version="1.0.0")

model = None
tokenizer = None
executor = ThreadPoolExecutor(max_workers=4)


class PredictionRequest(BaseModel):
    text: str
    max_length: int = 512


class PredictionResponse(BaseModel):
    label: str
    score: float
    latency_ms: float


@app.on_event("startup")
async def load_model():
    global model, tokenizer
    model = AutoModelForSequenceClassification.from_pretrained(
        "./model_artifacts", torch_dtype=torch.float16
    ).to("cuda")
    tokenizer = AutoTokenizer.from_pretrained("./model_artifacts")
    model.eval()


@app.post("/predict", response_model=PredictionResponse)
async def predict(req: PredictionRequest):
    import time
    t0 = time.perf_counter()
    inputs = tokenizer(
        req.text, return_tensors="pt", truncation=True, max_length=req.max_length
    ).to("cuda")
    loop = asyncio.get_running_loop()
    with torch.no_grad():
        outputs = await loop.run_in_executor(executor, model, **inputs)
    probs = torch.softmax(outputs.logits, dim=-1)
    label_idx = probs.argmax().item()
    elapsed = (time.perf_counter() - t0) * 1000
    return PredictionResponse(
        label=model.config.id2label[label_idx],
        score=probs[0][label_idx].item(),
        latency_ms=elapsed,
    )
```

---

## 3. Quantization Techniques

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    QUANTIZATION COMPARISON DIAGRAM                           │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    QUALITY  ←──────→  COMPRESSION                      │   │
│  │                                                                      │   │
│  │  FP32 ████████████████████████████████████  100%   (baseline)        │   │
│  │  FP16 ████████████████████████████████      50%   (negligible loss) │   │
│  │  BF16 ████████████████████████████████      50%   (training-friendly)│   │
│  │  INT8 ████████████████████████              25%   (minor degradation)│   │
│  │  INT4 ██████████████████                    12.5% (noticeable loss) │   │
│  │  FP8  ██████████████████████████            25%   (H100 promising)   │   │
│  │                                                                      │   │
│  │  ── Methods ──────────────────────────────────────────────────       │   │
│  │                                                                      │   │
│  │  ┌─────────┬──────────┬───────────┬──────────┬──────────┐          │   │
│  │  │ Method  │ Bits     │ Calibration│ Speed    │ Use Case │          │   │
│  │  ├─────────┼──────────┼───────────┼──────────┼──────────┤          │   │
│  │  │ GPTQ    │ 4/8-bit  │ Required   │ Slow load │ GPU-only │          │   │
│  │  │ AWQ     │ 4-bit    │ Required   │ Fast load │ GPU+CPU  │          │   │
│  │  │ GGUF    │ 2-8 bit  │ Built-in   │ Fast     │ CPU/edge │          │   │
│  │  │ BnB NF4 │ 4-bit    │ None (RT)  │ Fast     │ Training │          │   │
│  │  │ SmoothQ │ 8-bit   │ Required   │ Fast     │ LLM      │          │   │
│  │  └─────────┴──────────┴───────────┴──────────┴──────────┘          │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │              ACCURACY vs SIZE TRADE-OFF (Llama-2-70B)                │   │
│  │                                                                      │   │
│  │  Accuracy (%)                                                        │   │
│  │  100│ ─■─ FP16 (138 GB)                                              │   │
│  │   95│   ╲                                                             │   │
│  │   90│    ╲── AWQ 4-bit (36 GB)                                       │   │
│  │   85│      ╲                                                          │   │
│  │   80│       ╲── GPTQ 4-bit (35 GB)                                   │   │
│  │   75│         ╲                                                       │   │
│  │   70│          ╲── GGUF Q4_K_M (40 GB)                               │   │
│  │   65│            ╲                                                    │   │
│  │   60│             ╲── GGUF Q2_K (26 GB) ← quality cliff              │   │
│  │      └──────────────────────────────────────────                      │   │
│  │        20    40    60    80   100   120   140   (GB)                  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Post-Training Quantization (PTQ) — GPTQ

GPTQ uses second-order Hessian information to minimize reconstruction error layer-by-layer. One-shot: calibrate on ~128 samples, then quantize offline.

```python
from auto_gptq import AutoGPTQForCausalLM, BaseQuantizeConfig
from transformers import AutoTokenizer

model_id = "meta-llama/Llama-3.1-70B-Instruct"

quantize_config = BaseQuantizeConfig(
    bits=4,
    group_size=128,          # Group size for weight quantization
    desc_act=True,            # Activation-order-aware quantization
    damp_percent=0.01,        # Dampening for numerical stability
    sym=True,                 # Symmetric quantization ranges
)

model = AutoGPTQForCausalLM.from_pretrained(model_id, quantize_config)
tokenizer = AutoTokenizer.from_pretrained(model_id)

# Calibration data — ~128 representative samples
calib_data = load_calibration_data("pileval", n_samples=128, seq_len=2048)
calib_data_tokenized = [tokenizer(s) for s in calib_data]

model.quantize(calib_data_tokenized)
model.save_quantized("./llama-3.1-70b-gptq-4bit")
```

### 3.2 Activation-aware Weight Quantization (AWQ)

AWQ protects salient (outlier) weight channels by scaling them before quantization, preserving model quality with minimal calibration.

```python
from awq import AutoAWQForCausalLM

model = AutoAWQForCausalLM.from_pretrained(model_id)
tokenizer = AutoTokenizer.from_pretrained(model_id)

quant_config = {
    "zero_point": True,
    "q_group_size": 128,
    "w_bit": 4,
    "version": "GEMM",
}

model.quantize(tokenizer, quant_config=quant_config)
model.save_quantized("./llama-3.1-70b-awq-4bit")
```

**Why AWQ over GPTQ in many deployments:**
- Faster dequantization via GEMM kernel (no dequantization overhead at inference time).
- Memory-mappable `.safetensors` format enables partial GPU offloading.
- Better community support via vLLM / TGI integration.

### 3.3 GGUF / llama.cpp Quantization

GGUF supports 2-bit through 8-bit quantization in a single file, runs on CPU, GPU, or hybrid.

```bash
# Convert HF model to GGUF
python convert_hf_to_gguf.py ./llama-3.1-70b --outtype f16 --outfile llama-70b-f16.gguf

# Quantize to Q4_K_M (recommended quality/speed balance)
./llama-quantize llama-70b-f16.gguf llama-70b-Q4_K_M.gguf Q4_K_M

# Serve with llama.cpp server
./llama-server \
    -m llama-70b-Q4_K_M.gguf \
    -ngl 40 \
    -c 8192 \
    --port 8080 \
    -t 8
```

**GGUF quantization type selection guide:**

| Type | Bits/Weight | Model Size | Quality | Speed | Rec. Use Case |
|---|---|---|---|---|---|
| Q2_K | ~2.6 | Smallest | Poor | Slow | Memory-constrained exploration |
| Q3_K_M | ~3.4 | Very small | Fair | Moderate | Low-importance tasks |
| Q4_K_M | ~4.8 | Small | Good | Fast | **General purpose (recommended)** |
| Q5_K_M | ~5.7 | Moderate | Very Good | Fast | High-quality, space-constrained |
| Q6_K | ~6.6 | Large | Excellent | Fast | Near-FP16 quality |
| Q8_0 | 8.0 | Full | Near-lossless | Fast | Maximum quality |

### 3.4 bitsandbytes (NF4 / INT8)

```python
from transformers import AutoModelForCausalLM, BitsAndBytesConfig

bnb_config_4bit = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",          # NormalFloat4 — optimal for LLMs
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quantization=True,  # Nested quant for weight savings
)

bnb_config_8bit = BitsAndBytesConfig(
    load_in_8bit=True,
    llm_int8_threshold=6.0,             # Outlier threshold
)

model = AutoModelForCausalLM.from_pretrained(
    model_id,
    quantization_config=bnb_config_4bit,
    device_map="auto",
)
```

### 3.5 Quantization Decision Framework

```
                    Need to serve an LLM?
                           │
                    ┌──────┴──────┐
                    │  GPU avail?  │
                    ├─────┬───────┤
                   YES    │       NO
                    │     │        │
                    ▼     │        ▼
              ┌──────────┐│  ┌──────────┐
              │ vLLM/TGI ││  │ llama.cpp│
              │ server   ││  │ + GGUF   │
              └─────┬────┘│  └──────────┘
                    │     │
               ┌────┴────┐│
               │Quality  ││
               │budget?  ││
          ┌────┼────┐   ││
       High   │  Low   ││
          │   │    │   ││
          ▼   │    ▼   ││
    ┌──────┐  │┌──────┐││
    │ AWQ  │  ││ GPTQ │││
    │ 4-bit│  ││ 4-bit│││
    └──────┘  │└──────┘││
          │   │        ││
          ▼   │        ▼│
    ┌──────────┐  ┌──────────┐
    │ INT8/W8A8│ │ INT8/RT  │
    │ (BranchOut│ │ (BnB NF4)│
    │  Quant) │ │  QLoRA   │
    └──────────┘  └──────────┘
```

---

## 4. Model Optimization

### 4.1 Pruning

Remove redundant weights or entire structures from a model to reduce FLOPs and memory.

**Unstructured pruning** zeros individual weights (sparse but hardware-unfriendly):

```python
import torch.nn.utils.prune as prune

for name, module in model.named_modules():
    if isinstance(module, torch.nn.Linear):
        prune.l1_unstructured(module, name="weight", amount=0.3)
        prune.remove(module, "weight")  # Make pruning permanent
```

**Structured pruning** removes entire heads, layers, or channels (dense output, hardware-friendly):

```python
# Wanda pruning (prune by weight × activation magnitude)
from wanda.prune import wanda_prune

pruned_model = wanda_prune(
    model,
    calibration_data=calib_dataloader,
    sparsity_ratio=0.5,        # Remove 50% of weights
    prune_n=2,                  # N:M sparsity pattern (2:4)
    prune_m=4,
)
```

| Method | Granularity | Hardware Friendly | Accuracy Retention |
|---|---|---|---|
| L1/L2 Unstructured | Weight-level | No (sparse) | High |
| Wanda | Weight-level (activation-aware) | No (sparse) | Higher |
| SparseGPT | Weight-level | Partial (2:4) | High |
| ShortGPT | Layer-level | Yes | High (up to 25% layers removable) |
| SliceGPT | Head/Channel-level | Yes | Moderate |

### 4.2 Knowledge Distillation

Train a smaller **student** model to mimic a larger **teacher** model's output distribution.

```python
import torch
import torch.nn as nn
import torch.nn.functional as F


class DistillationLoss(nn.Module):
    def __init__(self, temperature: float = 4.0, alpha: float = 0.7):
        super().__init__()
        self.temperature = temperature
        self.alpha = alpha

    def forward(self, student_logits, teacher_logits, labels):
        soft_loss = F.kl_div(
            F.log_softmax(student_logits / self.temperature, dim=-1),
            F.softmax(teacher_logits / self.temperature, dim=-1),
            reduction="batchmean",
        ) * (self.temperature ** 2)

        hard_loss = F.cross_entropy(student_logits, labels)
        return self.alpha * soft_loss + (1 - self.alpha) * hard_loss
```

**Distillation strategies for LLMs:**

| Strategy | Teacher | Student | Notes |
|---|---|---|---|
| Logit mimicking | Llama-3-70B | Llama-3-8B | Standard KD |
| Progressive stacking | Llama-3-70B | 1B → 8B (grow) | Gradually add layers |
| Feature mimicking | Llama-3-70B | Llama-3-8B | Match intermediate repr. |
| Self-distillation | Llama-3-70B | Llama-3-70B (early exit) | Exit early on easy inputs |

### 4.3 Compilation — TensorRT

```python
import torch
from torch_tensorrt import compile

model = torch.jit.trace(model, example_input)

trt_model = compile(
    model,
    inputs=[torch.randint(0, 32000, (1, 128))],
    enabled_precisions={torch.float16, torch.int8},
    calibrator=calibrator,       # Required for INT8
    workspace_size=1 << 30,      # 1 GB workspace
)

# Save and reload
torch.jit.save(trt_model, "model_trt.pt")
```

### 4.4 ONNX Export & Optimization

```python
import torch
from onnxruntime.quantization import quantize_dynamic, QuantType

torch.onnx.export(
    model,
    example_input,
    "model.onnx",
    opset_version=17,
    input_names=["input_ids", "attention_mask"],
    output_names=["logits"],
    dynamic_axes={
        "input_ids": {0: "batch", 1: "seq_len"},
        "attention_mask": {0: "batch", 1: "seq_len"},
    },
)

quantize_dynamic(
    "model.onnx",
    "model_int8.onnx",
    weight_type=QuantType.QInt8,
)
```

---

## 5. Containerization & Orchestration

### 5.1 Docker Best Practices for ML

```dockerfile
# ============================================================
# Multi-stage Dockerfile for vLLM serving
# ============================================================

# ---------- Build stage ----------
FROM nvidia/cuda:12.4.0-devel-ubuntu22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 python3.11-venv python3-pip git curl && \
    rm -rf /var/lib/apt/lists/*

RUN python3.11 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir vllm==0.6.0

# ---------- Runtime stage ----------
FROM nvidia/cuda:12.4.0-runtime-ubuntu22.04 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 libibverbs1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Non-root user for security
RUN groupadd -g 1000 mlsrv && useradd -u 1000 -g mlsrv -m mlsrv
USER mlsrv

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

ENTRYPOINT ["python", "-m", "vllm.entrypoints.openai.api_server"]
CMD ["--model", "meta-llama/Llama-3.1-70B-Instruct", "--tensor-parallel-size", "4"]
```

### 5.2 Kubernetes Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    KUBERNETES-BASED SERVING ARCHITECTURE                         │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────┐                │
│  │                     Ingress Controller (Istio/NGINX)         │                │
│  │   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │                │
│  │   │ Rate-Limit   │    │ TLS Term.    │    │ Auth (JWT)   │   │                │
│  │   │ (10k req/s)  │    │              │    │ Validation   │   │                │
│  │   └──────────────┘    └──────────────┘    └──────────────┘   │                │
│  └─────────────────────────┬────────────────────────────────────┘                │
│                            │                                                     │
│                            ▼                                                     │
│  ┌──────────────────────────────────────────────────────────────┐                │
│  │                    Service Mesh (Istio Sidecar)              │                │
│  └─────────────────────────┬────────────────────────────────────┘                │
│                            │                                                     │
│            ┌───────────────┼───────────────┐                                     │
│            ▼               ▼               ▼                                     │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐                     │
│  │  Deployment     │ │  Deployment     │ │  Deployment     │                     │
│  │  v1 (stable)    │ │  v2 (canary)    │ │  v3 (A/B)       │                     │
│  │  3 replicas     │ │  1 replica      │ │  2 replicas      │                     │
│  │                 │ │                 │ │                  │                     │
│  │ ┌─────────────┐│ │ ┌─────────────┐│ │ ┌─────────────┐ │                     │
│  │ │  Pod        ││ │ │  Pod        ││ │ │  Pod        │ │                     │
│  │ │ ┌─────────┐ ││ │ │ ┌─────────┐ ││ │ │ ┌─────────┐ │ │                     │
│  │ │ │ vLLM    │ ││ │ │ │ vLLM    │ ││ │ │ │ vLLM    │ │ │                     │
│  │ │ │ Llama70b│ ││ │ │ │ Llama8b │ ││ │ │ │ Llama70b│ │ │                     │
│  │ │ │ AWQ-4bit│ ││ │ │ │ FP16    │ ││ │ │ │ INT8    │ │ │                     │
│  │ │ └─────────┘ ││ │ │ └─────────┘ ││ │ │ └─────────┘ │ │                     │
│  │ │ + sidecar  ││ │ │ + sidecar   ││ │ │ + sidecar  │ │                     │
│  │ └─────────────┘│ │ └─────────────┘│ │ └─────────────┘ │                     │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘                     │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────┐                │
│  │                    Control Plane                             │                │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐         │                │
│  │  │ HPA / KPA    │ │ Prometheus   │ │ ArgoCD /     │         │                │
│  │  │ Auto-scaler  │ │ Operator     │ │ Flux CD      │         │                │
│  │  └──────────────┘ └──────────────┘ └──────────────┘         │                │
│  └──────────────────────────────────────────────────────────────┘                │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────┐                │
│  │                    Data Plane                                │                │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐         │                │
│  │  │ PVC (Model   │ │ Shared GPU   │ │ Redis /      │         │                │
│  │  │  Weights)    │ │ Time-slicing │ │ Dragonfly    │         │                │
│  │  └──────────────┘ └──────────────┘ └──────────────┘         │                │
│  └──────────────────────────────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 5.3 Helm Chart

```yaml
# values.yaml
replicaCount: 2

image:
  repository: ghcr.io/org/vllm-server
  tag: v0.6.0-llama70b
  pullPolicy: IfNotPresent

model:
  name: "meta-llama/Llama-3.1-70B-Instruct"
  quantization: "awq"
  tensorParallelSize: 4
  maxModelLen: 8192
  downloadUrl: "s3://models/llama-3.1-70b-awq/"

resources:
  limits:
    nvidia.com/gpu: 4
    memory: "128Gi"
    cpu: "16"
  requests:
    nvidia.com/gpu: 4
    memory: "128Gi"
    cpu: "16"

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 8
  targetCPUUtilization: 70
  targetGPUUtilization: 80
  targetLatencyMs: 200

serviceMonitor:
  enabled: true
  interval: 15s

podDisruptionBudget:
  minAvailable: 1

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app: vllm-server
          topologyKey: kubernetes.io/hostname
```

---

## 6. CI/CD for ML

### 6.1 ML Pipeline Architecture

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                       ML CI/CD PIPELINE ARCHITECTURE                              │
│                                                                                    │
│  ┌───────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐          │
│  │  Git Push  │──>│  CI Pipeline │──>│  CD Pipeline │──>│  Production  │          │
│  │  (code +  │   │  (validate)  │   │  (deploy)    │   │  (serve)     │          │
│  │  config)  │   │              │   │              │   │              │          │
│  └───────────┘   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘          │
│                         │                  │                  │                    │
│            ┌────────────┼────────────────┐  │  ┌──────────────┼────────────┐     │
│            │            ▼                │  │  │              ▼             │     │
│            │  ┌─────────────────────┐    │  │  │  ┌─────────────────────┐  │     │
│            │  │ Lint + Type Check   │    │  │  │  │ Docker Build + Push │  │     │
│            │  │ (ruff/mypy/pyright) │    │  │  │  │ Multi-stage build    │  │     │
│            │  └─────────────────────┘    │  │  │  └─────────────────────┘  │     │
│            │  ┌─────────────────────┐    │  │  │  ┌─────────────────────┐  │     │
│            │  │ Unit Tests           │    │  │  │  │ Staging Deploy       │  │     │
│            │  │ (pytest)             │    │  │  │  │ (canary 5%)          │  │     │
│            │  └─────────────────────┘    │  │  │  └─────────────────────┘  │     │
│            │  ┌─────────────────────┐    │  │  │  ┌─────────────────────┐  │     │
│            │  │ Data Validation      │    │  │  │  │ Smoke Tests          │  │     │
│            │  │ (Great Expectations) │    │  │  │  │ (latency, accuracy)  │  │     │
│            │  └─────────────────────┘    │  │  │  └─────────────────────┘  │     │
│            │  ┌─────────────────────┐    │  │  │  ┌─────────────────────┐  │     │
│            │  │ Model Validation     │    │  │  │  │ Progressive Rollout │  │     │
│            │  │ (metrics threshold)  │    │  │  │  │ (5% → 25% → 100%)  │  │     │
│            │  └─────────────────────┘    │  │  │  └─────────────────────┘  │     │
│            └─────────────────────────────┘  │  └────────────────────────────┘     │
│                                            │                                      │
│  ┌─────────────────────────────────────────┼──────────────────────────────────┐  │
│  │               INFRASTRUCTURE AS CODE    │                                  │  │
│  │  ┌──────────┐  ┌──────────┐  ┌─────────┴┐  ┌──────────┐  ┌──────────┐  │  │
│  │  │ MLflow   │  │ W&B      │  │ DVC       │  │ ArgoCD   │  │ Terraform │  │  │
│  │  │ (model   │  │ (experi- │  │ (data     │  │ (GitOps  │  │ (infra    │  │  │
│  │  │  reg.)   │  │  ments)  │  │  version) │  │  deploy) │  │  prov.)   │  │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 MLflow — Model Registry & Experiment Tracking

```python
import mlflow
from mlflow.models import infer_signature

mlflow.set_tracking_uri("https://mlflow.internal.company.com")
mlflow.set_experiment("sentiment-classifier-v3")

with mlflow.start_run(run_name="llama-3.1-8b-awq-finetune"):
    mlflow.log_params({
        "base_model": "meta-llama/Llama-3.1-8B-Instruct",
        "quantization": "awq-4bit",
        "learning_rate": 2e-5,
        "epochs": 3,
        "lora_rank": 16,
        "lora_alpha": 32,
        "dataset": "imdb-v2-train",
    })

    # ... training loop ...

    mlflow.log_metrics({
        "eval_accuracy": 0.943,
        "eval_f1": 0.941,
        "eval_loss": 0.178,
        "inference_latency_p99_ms": 45.2,
    })

    signature = infer_signature(
        model_input={"text": ["This movie was great!"]},
        model_output={"label": ["POSITIVE"], "score": [0.98]},
    )

    mlflow.pyfunc.log_model(
        artifact_path="model",
        python_model=serve_wrapper,
        artifacts={"model_weights": "./model_artifacts"},
        signature=signature,
        pip_requirements=[
            f"vllm==0.6.0",
            f"transformers==4.44.0",
            f"autoawq==0.2.6",
        ],
    )

    # Register model in Model Registry
    result = mlflow.register_model(
        f"runs:/{mlflow.active_run().info.run_id}/model",
        "sentiment-classifier",
    )
```

### 6.3 DVC — Data Versioning

```bash
# Initialize DVC in the repo
dvc init

# Track training data
dvc add data/train.parquet data/val.parquet
git add data/train.parquet.dvc data/val.parquet.dvc data/.gitignore
git commit -m "track training data with DVC"

# Push data to remote storage
dvc remote add -d s3remote s3://my-ml-bucket/dvc-store
dvc push

# Pull specific data version
git checkout v2.1.0
dvc pull
```

### 6.4 Great Expectations — Data Quality Gates

```python
import great_expectations as gx

context = gx.get_context()

# Define expectations for training data
suite = context.add_expectation_suite("training_data_quality")

suite.add_expectation(
    gx.expectations.ExpectColumnValuesToNotBeNull(column="text")
)
suite.add_expectation(
    gx.expectations.ExpectColumnValuesToBeBetween(
        column="label", min_value=0, max_value=4
    )
)
suite.add_expectation(
    gx.expectations.ExpectTableRowCountToBeGreaterThanOrEqual(10000)
)

# Validate as CI gate
checkpoint = context.add_or_update_checkpoint(
    name="training_data_gate",
    validations=[
        {"batch_request": batch_request, "expectation_suite_name": "training_data_quality"}
    ],
)
result = checkpoint.run()

if not result["success"]:
    raise RuntimeError("Data quality gate failed — blocking deployment")
```

---

## 7. Monitoring & Observability

### 7.1 Monitoring Dashboard Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    MONITORING DASHBOARD ARCHITECTURE                           │
│                                                                                │
│  ┌────────────────────────────────────────────────────────────────────┐        │
│  │                    Grafana Dashboards                               │        │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │        │
│  │  │ Model        │  │ Infra        │  │ Business     │             │        │
│  │  │ Performance  │  │ Resources    │  │ Metrics      │             │        │
│  │  │              │  │              │  │              │             │        │
│  │  │ • Accuracy   │  │ • GPU Util   │  │ • Revenue    │             │        │
│  │  │ • Latency    │  │ • Memory     │  │ • Conversion │             │        │
│  │  │ • Throughput │  │ • CPU/Mem    │  │ • User Sat.  │             │        │
│  │  │ • Error Rate │  │ • Disk I/O   │  │ • CTR         │             │        │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │        │
│  └────────────────────────────┬───────────────────────────────────────┘        │
│                               │                                                │
│  ┌────────────────────────────┼───────────────────────────────────────┐        │
│  │                    Prometheus + Thanos                         │        │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │        │
│  │  │ Prometheus   │  │ Thanos Sidecar│  │ Thanos Store │             │        │
│  │  │ (scrape)    │──>│ (upload to   │──>│ (long-term   │             │        │
│  │  │             │  │  S3)         │  │  storage)    │             │        │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │        │
│  └─────────────────────────────────────────────────────────────────────┘        │
│                               │                                                │
│  ┌────────────────────────────┼───────────────────────────────────────┐        │
│  │                    Metrics Exporters                            │        │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │        │
│  │  │ vLLM     │  │ Triton   │  │ Node     │  │ DCGM     │          │        │
│  │  │ Metrics  │  │ Metrics  │  │ Exporter │  │ Exporter │          │        │
│  │  │ Port     │  │ Port     │  │ Port     │  │ Port     │          │        │
│  │  │ :8000/m  │  │ :8002/m  │  │ :9100/m  │  │ :9400/m  │          │        │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘          │        │
│  └───────────────────────────────────────────────────────────────────┘        │
│                               │                                                │
│  ┌────────────────────────────┼───────────────────────────────────────┐        │
│  │                    Alerting Pipeline                           │        │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │        │
│  │  │ Alertmanager │  │ PagerDuty    │  │ Slack/Teams  │          │        │
│  │  │ (route +     │──>│ (on-call)    │──>│ (notify)    │          │        │
│  │  │  dedup)      │  │              │  │              │          │        │
│  │  └──────────────┘  └──────────────┘  └──────────────┘          │        │
│  └──────────────────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Key Metrics to Monitor

**Model Performance Metrics:**

| Metric | Description | Alert Threshold |
|---|---|---|
| `prediction_accuracy` | Ground-truth accuracy on live data | < baseline - 5% |
| `prediction_latency_p50` | Median inference latency | > SLA threshold |
| `prediction_latency_p99` | Tail latency | > 3× SLA threshold |
| `request_rate` | Requests per second | > cluster capacity |
| `error_rate` | 5xx error percentage | > 1% |
| `gpu_memory_utilization` | GPU VRAM usage % | > 95% |
| `kv_cache_utilization` | KV cache usage % | > 90% |
| `num_requests_running` | Concurrent requests | > max_num_seqs |
| `num_requests_waiting` | Queued requests | > 100 |
| `batch_queue_delay` | Time in batch queue | > 50ms |

**Data Drift Detection Metrics:**

| Type | Method | Implementation |
|---|---|---|
| **Covariate shift** | PSI (Population Stability Index) | `PSI = sum((actual_pct - expected_pct) * ln(actual_pct / expected_pct))` |
| **Concept drift** | Model accuracy decay over time | Rolling window comparison |
| **Feature drift** | KL divergence per feature | `scipy.stats.entropy(p_recent, q_baseline)` |
| **Prediction drift** | Distribution of predicted labels | KS test on predictions |

```python
import numpy as np
from scipy.stats import ks_2samp, entropy

def compute_psi(expected: np.ndarray, actual: np.ndarray, n_bins: int = 10) -> float:
    breakpoints = np.linspace(expected.min(), expected.max(), n_bins + 1)
    expected_pct = np.histogram(expected, bins=breakpoints)[0] / len(expected)
    actual_pct = np.histogram(actual, bins=breakpoints)[0] / len(actual)
    expected_pct = np.clip(expected_pct, 1e-6, None)
    actual_pct = np.clip(actual_pct, 1e-6, None)
    return float(np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct)))


def detect_drift(baseline_preds: np.ndarray, recent_preds: np.ndarray) -> dict:
    psi = compute_psi(baseline_preds, recent_preds)
    ks_stat, ks_p = ks_2samp(baseline_preds, recent_preds)
    return {
        "psi": psi,
        "psi_alert": psi > 0.2,
        "ks_statistic": ks_stat,
        "ks_pvalue": ks_p,
        "ks_alert": ks_p < 0.01,
    }
```

### 7.3 Custom Metrics Export — vLLM Example

```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server

PREDICTION_COUNT = Counter(
    "model_predictions_total",
    "Total predictions made",
    ["model_version", "endpoint"],
)

PREDICTION_LATENCY = Histogram(
    "model_prediction_latency_seconds",
    "Prediction latency in seconds",
    ["model_version"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

DRIFT_SCORE = Gauge(
    "model_drift_score",
    "Current data drift score (PSI)",
    ["model_name", "feature"],
)

def record_prediction(version: str, latency: float, endpoint: str = "predict"):
    PREDICTION_COUNT.labels(model_version=version, endpoint=endpoint).inc()
    PREDICTION_LATENCY.labels(model_version=version).observe(latency)

start_http_server(8080)
```

---

## 8. Auto-Scaling Strategies

### 8.1 Horizontal Pod Autoscaler (HPA) — GPU Metrics

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: vllm-server-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: vllm-server
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Pods
      pods:
        metric:
          name: num_requests_waiting
        target:
          type: AverageValue
          averageValue: "10"
    - type: Pods
      pods:
        metric:
          name: avg_request_latency_seconds
        target:
          type: AverageValue
          averageValue: "0.5"
    - type: Resource
      resource:
        name: nvidia.com/gpu_memory_utilization
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 30
      policies:
        - type: Pods
          value: 2
          periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Pods
          value: 1
          periodSeconds: 120
      selectPolicy: Min
```

### 8.2 KPA — Knative Pod Autoscaler

KPA scales based on **concurrency** rather than CPU, making it ideal for request-driven inference:

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: sentiment-classifier
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/target: "10"          # Target concurrency
        autoscaling.knative.dev/targetBurstCapacity: "5"
        autoscaling.knative.dev/min-scale: "1"
        autoscaling.knative.dev/max-scale: "20"
        autoscaling.knative.dev/scale-to-zero: "false"
        autoscaling.knative.dev/panic-window: "60s"
        autoscaling.knative.dev/panic-threshold-percentage: "200"
    spec:
      containerConcurrency: 20                       # Max concurrent requests per pod
      containers:
        - image: ghcr.io/org/sentiment-server:v2.1.0
          resources:
            limits:
              nvidia.com/gpu: 1
```

### 8.3 Custom Metrics Pipeline

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Model       │───>│  Prometheus  │───>│  Custom      │───>│  HPA / KPA   │
│  Server      │    │  Adapter     │    │  Metrics     │    │  Controller  │
│  (vLLM/TGI)  │    │  (Prometheus │    │  API         │    │              │
│              │    │   Adapter)   │    │              │    │              │
└─────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
                                              ▲
                                              │
                                   ┌──────────┴──────────┐
                                   │  Metrics Server     │
                                   │  (exposes custom   │
                                   │   metrics to HPA)  │
                                   └─────────────────────┘
```

**Critical scaling parameters for LLM serving:**

| Parameter | Formula | Example |
|---|---|---|
| Max concurrent requests | `max_num_seqs × replica_count` | `256 × 4 = 1024` |
| Tokens/second capacity | `tokens_per_sec × replica × TP_size` | `4000 × 4 × 4 = 64000` |
| Memory per replica | `model_size / TP + KV_cache + overhead` | `35GB/4 + 10GB + 2GB = 20.75GB/GPU` |
| Scale-up trigger | `queue_depth > threshold` OR `latency_p99 > SLA` | Queue > 10 OR p99 > 500ms |
| Scale-down delay | Model loading time + warm-up | 5 min for 70B model |

---

## 9. A/B Testing & Canary Deployments

### 9.1 A/B Testing and Canary Deployment Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│              A/B TESTING & CANARY DEPLOYMENT FLOW                               │
│                                                                                  │
│  ┌─────────────┐                                                                │
│  │  Traffic     │                                                                │
│  │  Splitter    │                                                                │
│  │ (Istio/Envoy)│                                                                │
│  └──────┬──────┘                                                                │
│         │                                                                        │
│    ┌────┴─────────────────────┐                                                 │
│    │  VirtualService Routing   │                                                 │
│    │                          │                                                  │
│    │  ┌──── A/B Test ────┐   │   ┌──── Canary ──────────┐                     │
│    │  │                   │   │   │                       │                     │
│    │  │  50% → Model A    │   │   │  95% → Model A (stable)│                    │
│    │  │  50% → Model B    │   │   │   5% → Model B (canary)│                    │
│    │  │                   │   │   │                       │                     │
│    │  │  Metric Compare:  │   │   │  Monitor for:         │                     │
│    │  │  • Accuracy       │   │   │  • Error rate < 1%    │                     │
│    │  │  • Latency        │   │   │  • Latency p99 < SLA  │                     │
│    │  │  • User engagement│   │   │  • No crashes         │                     │
│    │  │  • Revenue impact│   │   │                       │                     │
│    │  └──────────────────┘   │   └───────────────────────┘                     │
│    └─────────────────────────┘                                                 │
│         │                                                                        │
│         ▼                                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐          │
│  │                    Decision Gate (Automated)                     │          │
│  │                                                                   │          │
│  │   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐        │          │
│  │   │ Statistically │    │  Latency     │    │  Error Rate  │        │          │
│  │   │ Significant?  │    │  within SLA? │    │  < 1%?      │        │          │
│  │   └──────┬───────┘    └──────┬───────┘    └──────┬───────┘        │          │
│  │          │                   │                   │                 │          │
│  │    ┌─────┴─────┐       ┌────┴────┐        ┌────┴────┐           │          │
│  │    │YES       NO│       │YES    NO│        │YES    NO│           │          │
│  │    ▼           ▼        ▼         ▼         ▼        ▼            │          │
│  │  ┌───┐     ┌──────┐ ┌───┐   ┌──────┐  ┌───┐  ┌──────┐          │          │
│  │  │ROL│     │EXTEND│ │ROL│   │ROLLOUT│ │ROL│  │ROLLBACK│         │          │
│  │  │LOUT│     │TEST │ │LOUT│   │BACK  │ │LOUT│  │      │          │          │
│  │  └───┘     └──────┘ └───┘   └──────┘  └───┘  └──────┘          │          │
│  └───────────────────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Istio Traffic Splitting

```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: model-vs
spec:
  hosts:
    - model-service.production.svc.cluster.local
  http:
    - match:
        - headers:
            x-model-version:
              exact: "v2"
      route:
        - destination:
            host: model-service
            subset: v2
    - route:
        - destination:
            host: model-service
            subset: v1
          weight: 95
        - destination:
            host: model-service
            subset: v2
          weight: 5
```

### 9.3 Statistical Significance Testing

```python
import numpy as np
from scipy import stats


def ab_test_significance(
    control_conversions: int,
    control_total: int,
    treatment_conversions: int,
    treatment_total: int,
    alpha: float = 0.05,
    min_detectable_effect: float = 0.02,
) -> dict:
    p_control = control_conversions / control_total
    p_treatment = treatment_conversions / treatment_total

    pooled_p = (control_conversions + treatment_conversions) / (
        control_total + treatment_total
    )

    se = np.sqrt(
        pooled_p * (1 - pooled_p) * (1 / control_total + 1 / treatment_total)
    )

    z_score = (p_treatment - p_control) / se
    p_value = 2 * (1 - stats.norm.cdf(abs(z_score)))

    effect_size = p_treatment - p_control
    conf_lower = effect_size - 1.96 * se
    conf_upper = effect_size + 1.96 * se

    return {
        "p_control": p_control,
        "p_treatment": p_treatment,
        "effect_size": effect_size,
        "confidence_interval": (conf_lower, conf_upper),
        "z_score": z_score,
        "p_value": p_value,
        "significant": p_value < alpha,
        "practical_significance": abs(effect_size) >= min_detectable_effect,
        "recommendation": (
            "roll_out_treatment"
            if p_value < alpha and effect_size > min_detectable_effect
            else "keep_control"
        ),
    }
```

### 9.4 Canary Rollout with Argo Rollouts

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: model-server
spec:
  replicas: 8
  strategy:
    canary:
      canaryService: model-server-canary
      stableService: model-server-stable
      steps:
        - setWeight: 5
        - pause: { duration: 5m }
        - setWeight: 10
        - pause: { duration: 5m }
        - setWeight: 25
        - pause: { duration: 10m }
        - setWeight: 50
        - pause: { duration: 10m }
        - setWeight: 100
      analysis:
        templates:
          - templateName: model-performance
        startingStep: 2
        args:
          - name: canary-service
            value: model-server-canary

  analysisTemplates:
    - templateName: model-performance
      metrics:
        - name: error-rate
          provider:
            prometheus:
              address: http://prometheus.monitoring:9090
              query: |
                sum(rate(http_requests_total{service="{{args.canary-service}}",code=~"5.."}[5m]))
                /
                sum(rate(http_requests_total{service="{{args.canary-service}}"}[5m]))
          successCondition: result[0] < 0.01
          failureLimit: 3
        - name: latency-p99
          provider:
            prometheus:
              address: http://prometheus.monitoring:9090
              query: |
                histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket{service="{{args.canary-service}}"}[5m])) by (le))
          successCondition: result[0] < 0.5
          failureLimit: 3
```

---

## 10. Cost Optimization

### 10.1 Cost Optimization Decision Tree

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    COST OPTIMIZATION DECISION TREE                              │
│                                                                                  │
│                         What is your workload type?                             │
│                              │                                                   │
│                ┌─────────────┼──────────────┐                                    │
│                ▼             ▼              ▼                                    │
│           ┌────────┐  ┌──────────┐  ┌───────────┐                               │
│           │Batch   │  │Real-Time │  │Sporadic   │                               │
│           │(periodic)│ │(always-on)│ │(low QPS)  │                               │
│           └────┬───┘  └─────┬────┘  └─────┬─────┘                               │
│                │            │             │                                      │
│                ▼            ▼             ▼                                      │
│           ┌────────┐  ┌──────────┐  ┌───────────┐                               │
│           │Spot    │  │Reserved  │  │Serverless │                               │
│           │Instances│ │Instances │  │(SageMaker │                               │
│           │         │ │(1yr/3yr) │  │Serverless │                               │
│           │+ Check- │ │+ Savings │  │ Endpoints │                               │
│           │  pointing│ │  Plans   │  │ or CF     │                               │
│           └────┬───┘  └─────┬────┘  └─────┬─────┘                               │
│                │            │             │                                      │
│                ▼            ▼             ▼                                      │
│           ┌────────────────────────────────────────────────────────┐            │
│           │             FURTHER OPTIMIZATION                     │            │
│           │                                                        │            │
│           │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │            │
│           │  │ GPU Sharing   │  │ Quantization  │  │ Model       │ │            │
│           │  │ • Time-slice │  │ • INT8/INT4   │  │ Caching     │ │            │
│           │  │ • MPS         │  │ • AWQ/GPTQ    │  │ • Redis     │ │            │
│           │  │ • MIG         │  │ • GGUF        │  │ • Semantic  │ │            │
│           │  └──────────────┘  └──────────────┘  └─────────────┘ │            │
│           │                                                        │            │
│           │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │            │
│           │  │ Multi-model  │  │ Infer. Server │  │ Speculative │ │            │
│           │  │ Packing      │  │ Optimizations  │  │ Decoding    │ │            │
│           │  │ • Triton     │  │ • KV Cache    │  │ • Draft     │ │            │
│           │  │ • Batching   │  │   Sharing     │  │   model     │ │            │
│           │  └──────────────┘  └──────────────┘  └─────────────┘ │            │
│           └────────────────────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 10.2 GPU Sharing Strategies

**NVIDIA Multi-Instance GPU (MIG):**

```bash
# Partition an A100 into 7 instances (1g.5gb each)
nvidia-smi mig -cgi 1g.5gb,1g.5gb,1g.5gb,1g.5gb,1g.5gb,1g.5gb,1g.5gb
nvidia-smi mig -gi 0 -C 1g.5gb,1g.5gb,1g.5gb,1g.5gb,1g.5gb,1g.5gb,1g.5gb
```

**Time-slicing (consumer GPUs / non-MIG):**

```yaml
# In Kubernetes device plugin config
sharing:
  timeSlicing:
    renameByDefault: false
    failRequestsGreaterThanOne: true
    resources:
      - name: nvidia.com/gpu
        replicas: 4   # Each GPU appears as 4 virtual GPUs
```

**GPU cost comparison (as of 2025, US-East):**

| Instance | GPU | $/hr On-Demand | $/hr 1yr RI | $/hr Spot | GPU Memory |
|---|---|---|---|---|---|
| p4d.24xlarge | 8× A100 80GB | $32.77 | $20.50 | ~$10.00 | 640 GB |
| p5.48xlarge | 8× H100 80GB | $98.32 | $61.00 | ~$30.00 | 640 GB |
| g5.12xlarge | 4× A10G 24GB | $5.67 | $3.50 | ~$1.70 | 96 GB |
| g6.12xlarge | 4× L4 24GB | $4.50 | $2.80 | ~$1.35 | 96 GB |

### 10.3 Spot Instance Strategy for Batch Workloads

```python
import boto3
import time

ec2 = boto3.client("ec2", region_name="us-east-1")

SPOT_FLEET_CONFIG = {
    "IamFleetRole": "arn:aws:iam::123456789012:role/aws-ec2-spot-fleet-tagging-role",
    "AllocationStrategy": "capacityOptimized",
    "TargetCapacitySpecification": {"TotalTargetCapacity": 16, "OnDemandTargetCapacity": 2},
    "SpotMaintenanceStrategies": {
        "CapacityRebalance": {"ReplacementStrategy": "launch-before-terminate"}
    },
    "LaunchTemplateConfigs": [
        {
            "LaunchTemplateSpecification": {
                "LaunchTemplateId": "lt-0abc1234",
                "Version": "$Latest",
            },
            "Overrides": [
                {"InstanceType": "p4d.24xlarge", "SubnetId": "subnet-xxx"},
                {"InstanceType": "p4de.24xlarge", "SubnetId": "subnet-xxx"},
            ],
        }
    ],
}


def launch_spot_training(job_name: str, model_config: dict):
    response = ec2.request_spot_fleet(SpotFleetRequestConfig=SPOT_FLEET_CONFIG)
    fleet_id = response["SpotFleetRequestId"]
    print(f"Launched spot fleet {fleet_id} for {job_name}")
    return fleet_id
```

**Checkpointing strategy for spot interruption:**

```python
import torch
import signal
import os


class SpotInterruptionHandler:
    def __init__(self, model, optimizer, checkpoint_dir="/tmp/checkpoints"):
        self.model = model
        self.optimizer = optimizer
        self.checkpoint_dir = checkpoint_dir
        os.makedirs(checkpoint_dir, exist_ok=True)
        signal.signal(signal.SIGTERM, self._handle_spot_termination)
        signal.signal(signal.SIGUSR2, self._handle_spot_termination)

    def _handle_spot_termination(self, signum, frame):
        print(f"Received signal {signum} — saving emergency checkpoint")
        self._save_checkpoint(is_emergency=True)
        exit(0)

    def _save_checkpoint(self, is_emergency: bool = False):
        prefix = "emergency" if is_emergency else "periodic"
        path = f"{self.checkpoint_dir}/{prefix}_ckpt_{int(time.time())}.pt"
        torch.save(
            {
                "model_state_dict": self.model.state_dict(),
                "optimizer_state_dict": self.optimizer.state_dict(),
                "step": self.global_step,
            },
            path,
        )
```

### 10.4 Serverless Inference

| Platform | Cold Start | Max GPU | Max Timeout | Cost Model |
|---|---|---|---|---|
| AWS Lambda + Custom Runtime | ~5s (warm) | None (CPU only) | 15 min | Per-invocation |
| SageMaker Serverless | ~10–60s | 1× A10G | 15 min | Per-compute-second |
| RunPod Serverless | ~3–15s | 1× A100/H100 | 10 min | Per-second |
| Modal | ~1–3s | 1× H100 | 10 min | Per-second |
| Replicate | ~5–20s | 1× A100 | varies | Per-second |

---

## 11. Security

### 11.1 Model Encryption at Rest

```python
from cryptography.fernet import Fernet
import os

def encrypt_model_artifacts(model_dir: str, output_dir: str, key: bytes = None):
    key = key or Fernet.generate_key()
    cipher = Fernet(key)

    os.makedirs(output_dir, exist_ok=True)

    for root, _, files in os.walk(model_dir):
        for fname in files:
            src_path = os.path.join(root, fname)
            rel_path = os.path.relpath(src_path, model_dir)
            dst_path = os.path.join(output_dir, rel_path + ".enc")
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)

            with open(src_path, "rb") as f:
                data = f.read()

            encrypted = cipher.encrypt(data)
            with open(dst_path, "wb") as f:
                f.write(encrypted)

    print(f"Encrypted model to {output_dir}")
    print(f"Store this key securely in Vault/KMS: {key.decode()}")
    return key


def decrypt_model_artifacts(encrypted_dir: str, output_dir: str, key: bytes):
    cipher = Fernet(key)
    os.makedirs(output_dir, exist_ok=True)

    for root, _, files in os.walk(encrypted_dir):
        for fname in files:
            if not fname.endswith(".enc"):
                continue
            src_path = os.path.join(root, fname)
            rel_path = os.path.relpath(src_path, encrypted_dir).removesuffix(".enc")
            dst_path = os.path.join(output_dir, rel_path)
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)

            with open(src_path, "rb") as f:
                encrypted = f.read()

            decrypted = cipher.decrypt(encrypted)
            with open(dst_path, "wb") as f:
                f.write(decrypted)
```

### 11.2 API Security — Rate Limiting & Auth

```python
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware import Middleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import jwt
import time

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)

JWT_SECRET = "your-256-bit-secret"  # Use AWS KMS / Vault in production
JWT_ALGORITHM = "HS256"

RATE_LIMITS = {
    "free": "10/minute",
    "basic": "60/minute",
    "premium": "600/minute",
    "enterprise": "6000/minute",
}


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload["exp"] < time.time():
            raise HTTPException(status_code=401, detail="Token expired")
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path in ("/health", "/metrics"):
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Missing token"})

    token = auth_header.removeprefix("Bearer ")
    payload = verify_token(token)
    request.state.user = payload
    request.state.tier = payload.get("tier", "free")

    return await call_next(request)


@app.post("/v1/chat/completions")
@limiter.limit(lambda request: RATE_LIMITS.get(request.state.tier, "10/minute"))
async def chat_completions(request: Request):
    tier = request.state.tier
    if tier == "free":
        max_tokens = 256
    elif tier == "basic":
        max_tokens = 1024
    elif tier == "premium":
        max_tokens = 4096
    else:
        max_tokens = 8192

    # ... process request ...
```

### 11.3 Kubernetes Security — Network Policies & Pod Security

```yaml
# Network Policy — restrict model serving pods to only accept traffic from ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: model-server-netpol
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: model-server
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
        - podSelector:
            matchLabels:
              app: api-gateway
      ports:
        - port: 8000
          protocol: TCP
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - port: 9090
    - to:
        - namespaceSelector:
            matchLabels:
              name: model-registry
      ports:
        - port: 443
---
# Pod Security Standard — restrict capabilities
apiVersion: v1
kind: Pod
metadata:
  name: model-server
  namespace: production
  labels:
    app: model-server
spec:
  serviceAccountName: model-server-sa
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: server
      image: ghcr.io/org/model-server:v2.1.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          nvidia.com/gpu: 1
          memory: "32Gi"
          cpu: "8"
        requests:
          nvidia.com/gpu: 1
          memory: "32Gi"
          cpu: "8"
      env:
        - name: MODEL_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: model-secrets
              key: encryption-key
      volumeMounts:
        - name: model-cache
          mountPath: /models
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: model-cache
      persistentVolumeClaim:
        claimName: model-weights-pvc
    - name: tmp
      emptyDir: {}
```

### 11.4 Model Supply Chain Security

```yaml
# Sigstore / Cosign verification — only allow signed model containers
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-model-container-signature
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-model-image-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        imageRefs:
          - "ghcr.io/org/model-server*"
        attestors:
          - entries:
              - keys:
                  public: |-
                    -----BEGIN PUBLIC KEY-----
                    <your-signing-public-key>
                    -----END PUBLIC KEY-----
        message: "Model container images must be signed with the org key"
```

### 11.5 Inference-Time Protections

| Threat | Mitigation | Implementation |
|---|---|---|
| **Prompt injection** | Input validation + guardrails | NVIDIA NeMo Guardrails, Llama Guard |
| **PII leakage** | Output filtering + redaction | Presidio, regex patterns |
| **Model extraction** | Rate limiting + watermarking | Per-user rate caps, statistical watermarks |
| **Adversarial inputs** | Input sanitization + anomaly detection | Detectors for jailbreak patterns |
| **Data poisoning** | Training data validation | Great Expectations schemas, data lineage |
| **Model inversion** | Differential privacy training | Opacus / TensorFlow Privacy |

---

## Appendix: Quick-Reference Commands

```bash
# vLLM serving
python -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Llama-3.1-70B-Instruct \
    --tensor-parallel-size 4 --quantization awq --port 8000

# TensorRT engine build
trtllm-build --model_dir ./llama-70b-hf \
    --quantize fp8 --tp_size 4 --output_dir ./trt_engines/llama-70b-fp8-tp4

# Docker build + push
docker build -t ghcr.io/org/model-server:v2.1.0 .
docker push ghcr.io/org/model-server:v2.1.0

# GPTQ quantization
python auto_gptq/quantize.py --model meta-llama/Llama-3.1-70B-Instruct \
    --bits 4 --group_size 128 --desc_act True --output_dir ./llama-70b-gptq-4bit

# GGUF quantization
./llama-quantize llama-70b-f16.gguf llama-70b-Q4_K_M.gguf Q4_K_M

# ONNX export + INT8 quantization
python -m onnxruntime.quantization.quantize_dynamic \
    --model_input model.onnx --model_output model_int8.onnx --weight_type QInt8

# Prometheus port-forward
kubectl port-forward -n monitoring svc/prometheus-operated 9090

# Helm deploy
helm upgrade --install model-server ./charts/model-server \
    --namespace production --values values-production.yaml
```

---

*This guide covers the full spectrum of model deployment and MLOps infrastructure—from choosing the right serving architecture and framework, through quantization and optimization, to production concerns like monitoring, scaling, testing, cost management, and security. Each section is designed to be independently referenceable while forming a cohesive end-to-end deployment narrative.*

---

## Real References

### Quantization & Compression

1. Frantar, E., Ashkboos, S., Hoefler, T., & Alistarh, D., "GPTQ: Accurate Post-Training Quantization for Generative Pre-trained Transformers", *ICLR 2023*, arXiv:2210.17323. https://arxiv.org/abs/2210.17323

2. Lin, J., Tang, J., Tang, H., Yang, S., Chen, W.-M., Wang, W.-C., Xiao, G., Dang, X., Gan, C., & Han, S., "AWQ: Activation-aware Weight Quantization for LLM Compression and Acceleration", *MLSys 2024*, arXiv:2306.00978. https://arxiv.org/abs/2306.00978

3. Dettmers, T., Lewis, M., Belkada, Y., & Zettlemoyer, L., "LLM.int8(): 8-bit Matrix Multiplication for Transformers at Scale", *NeurIPS 2022*, arXiv:2208.07339. https://arxiv.org/abs/2208.07339

4. Xiao, G., Lin, J., Seznec, M., Wu, H., Demouth, J., & Han, S., "SmoothQuant: Accurate and Efficient Post-Training Quantization for Large Language Models", *ICML 2023*, arXiv:2211.10438. https://arxiv.org/abs/2211.10438

5. Dettmers, T., Pagnoni, A., Holtzman, A., & Zettlemoyer, L., "QLoRA: Efficient Finetuning of Quantized LLMs", *NeurIPS 2023*, arXiv:2305.14314. https://arxiv.org/abs/2305.14314

6. Sun, M., Liu, Z., Bair, A., & Kolter, J. Z., "A Simple and Effective Pruning Approach for Large Language Models", *ICLR 2024*, arXiv:2306.11695. https://arxiv.org/abs/2306.11695

7. SparseGPT: Frantar, E., & Alistarh, D., "SparseGPT: Massive Language Models Can Be Accurately Pruned in One-Shot", *ICML 2023*, arXiv:2301.00774. https://arxiv.org/abs/2301.00774

8. Men, X., Leng, Q., Liang, M., et al., "ShortGPT: Layers in Large Language Models Are More Redundant Than You Realize", arXiv:2403.03853. https://arxiv.org/abs/2403.03853

### Inference Serving & Optimization

9. Kwon, W., Li, Z., Zhuang, S., et al., "Efficient Memory Management for Large Language Model Serving with PagedAttention", *SOSP 2023*, arXiv:2309.06180. https://arxiv.org/abs/2309.06180

10. Xia, H., Zhou, Z., Zheng, Z., & Chen, W., "Speculative Decoding: Exploiting Draft Models for Fast LLM Inference", arXiv:2302.01318. https://arxiv.org/abs/2302.01318

11. Kim, G., Xiao, G., Wu, H., et al., "Full Stack Optimization for Serving LLMs with TensorRT-LLM", NVIDIA Developer, https://developer.nvidia.com/tensorrt-llm

12. Gerganov, G., "llama.cpp: Port of Facebook's LLaMA model in C/C++", GitHub, https://github.com/ggerganov/llama.cpp

13. HuggingFace, "Text Generation Inference (TGI)", https://github.com/huggingface/text-generation-inference

14. vLLM Project, "vLLM: High-throughput and memory-efficient inference and serving engine for LLMs", https://docs.vllm.ai

15. NVIDIA, "Triton Inference Server", https://github.com/triton-inference-server/server

16. Narayanan, D., Shoeybi, M., Casper, J., et al., "Efficient Large-Scale Language Model Training on GPU Clusters Using Megatron-LM", *SC 2021*, arXiv:2104.04473. https://arxiv.org/abs/2104.04473

17. Pope, R., Douglas, S., Chowdhery, A., et al., "Efficiently Scaling Transformer Inference", *MLSys 2023*, arXiv:2211.05102. https://arxiv.org/abs/2211.05102

### Knowledge Distillation

18. Hinton, G., Vinyals, O., & Dean, J., "Distilling the Knowledge in a Neural Network", *NeurIPS 2014 Workshop*, arXiv:1503.02531. https://arxiv.org/abs/1503.02531

19. Sanh, V., Debut, L., Chaumond, J., & Wolf, T., "DistilBERT, a Distilled Version of BERT: Smaller, Faster, Cheaper and Lighter", *NeurIPS 2019 Workshop on Energy Efficient Machine Learning and Cognitive Computing*, arXiv:1910.01108. https://arxiv.org/abs/1910.01108

### Containerization & Kubernetes

20. Burns, B., Grant, B., Oppenheimer, D., Brewer, E., & Wilkes, J., "Borg, Omega, and Kubernetes", *ACM Queue*, vol. 14, no. 1, pp. 70–93, 2016. DOI: 10.1145/2898442.2898443

21. Kubernetes Documentation, "Horizontal Pod Autoscaler", https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/

22. Istio Documentation, "Traffic Management", https://istio.io/latest/docs/concepts/traffic-management/

23. Argo Rollouts Documentation, "Progressive Delivery with Argo Rollouts", https://argoproj.github.io/argo-rollouts/

24. Helm Documentation, "Helm: The Package Manager for Kubernetes", https://helm.sh/docs/

25. Sharif, O., Karajic, S., & NVIDIA, "GPU Sharing in Kubernetes: Time-Slicing, MPS, and MIG", NVIDIA Technical Blog, 2023. https://developer.nvidia.com/blog/improving-gpu-utilization-in-kubernetes/

### Model Serving Frameworks

26. KServe Documentation, "KServe: Kubernetes-native Model Serving", https://kserve.github.io

27. PyTorch, "TorchServe: Model Serving for PyTorch", https://pytorch.org/serve/

28. FastAPI, "FastAPI: Modern, Fast Web Framework for Building APIs with Python", https://fastapi.tiangolo.com/

29. ONNX Runtime Documentation, "ONNX Runtime: Cross-platform, High-Performance Scoring Engine", https://onnxruntime.ai/

30. TensorFlow, "TensorFlow Serving: Flexible, High-Performance Serving System for ML Models", https://www.tensorflow.org/tfx/guide/serving

### CI/CD & MLOps

31. Sculley, D., Holt, G., Golovin, D., et al., "Hidden Technical Debt in Machine Learning Systems", *NeurIPS 2015*, arXiv:1506.06476. https://arxiv.org/abs/1506.06476

32. Amershi, S., Begel, A., Bird, C., et al., "Software Engineering for Machine Learning: A Case Study", *ICSE 2019—SEIP*, DOI: 10.1109/ICSE-SEIP.2019.00009. https://www.microsoft.com/en-us/research/publication/software-engineering-for-machine-learning-a-case-study/

33. MLflow Documentation, "MLflow: A Platform for the Machine Learning Lifecycle", https://mlflow.org/docs/latest

34. DVC Documentation, "DVC: Data Version Control", https://dvc.org/doc

35. Great Expectations Documentation, "Great Expectations: Always Know What to Expect from Your Data", https://greatexpectations.io/

36. Zaharia, M., Chen, R., Ghodsi, A., et al., "Accelerating the Machine Learning Lifecycle with MLflow", *IEEE Data Engineering Bulletin*, vol. 41, no. 4, pp. 13–27, 2018.

37. Polydoros, D., & Bajic, N., "Argo Workflows: Container-Native Workflow Engine for Kubernetes", https://argoproj.github.io/argo-workflows/

### Monitoring & Observability

38. Prometheus Documentation, "Prometheus: Monitoring System & Time Series Database", https://prometheus.io/docs/

39. Grafana Labs, "Grafana: The Open Observability Platform", https://grafana.com/docs/

40. Thanos Documentation, "Thanos: Highly Available Prometheus Setup with Long-Term Storage", https://thanos.io/

41. Webb, S., et al., "Population Stability Index and Model Monitoring", *SAS Global Forum 2020*, paper SASGF2020-104.

42. Google SRE Team, "Site Reliability Engineering: How Google Runs Production Systems", O'Reilly Media, ISBN: 978-1-491-92911-8, 2016.

43. Netflix Technology Blog, "Chaos Engineering", https://netflix.github.io/chaosmonkey/ ; Rosenthal, C., & Jones, N., "Chaos Engineering: Building Confidence in System Behavior", *O'Reilly Media*, ISBN: 978-1-492-043727-6, 2020.

44. NVIDIA, "DCGM Exporter: GPU Metrics for Prometheus", https://github.com/NVIDIA/dcgm-exporter

### Auto-Scaling & Cost Optimization

45. Knative Documentation, "Knative Serving: Autoscaling", https://knative.dev/docs/serving/autoscaling/

46. AWS, "Amazon EC2 Spot Instances Best Practices", https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/best-practices-for-using-ec2-spot-instances.html

47. NVIDIA, "Multi-Instance GPU (MIG) User Guide", https://docs.nvidia.com/datacenter/tesla/mig-user-guide/

48. Xu, Y., et al., "SageMaker Serverless Inference", AWS Machine Learning Blog. https://docs.aws.amazon.com/sagemaker/latest/dg/serverless-endpoint.html

### Security

49. Microsoft, "Azure Machine Learning: Secure Scoring", https://learn.microsoft.com/en-us/azure/machine-learning/concept-enterprise-security

50. Sigstore, "Cosign: Container Signing, Verification, and Storage in an OCI Registry", https://github.com/sigstore/cosign

51. Kyverno Documentation, "Kyverno: Kubernetes Native Policy Management", https://kyverno.io/docs/

52. Reimers, S., Liu, Y., et al., "NVIDIA NeMo Guardrails: Building Trustworthy LLM Applications", https://github.com/NVIDIA/NeMo-Guardrails

53. Abadi, M., Chu, A., Goodfellow, I., et al., "Deep Learning with Differential Privacy", *CCS 2016*, arXiv:1607.00133. https://arxiv.org/abs/1607.00133

### ONNX & Model Portability

54. ONNX, "Open Neural Network Exchange", https://onnx.ai/

55. ONNX Runtime, "Quantization in ONNX Runtime", https://onnxruntime.ai/docs/performance/quantization.html

### Edge & Mobile Deployment

56. Apple, "Core ML Tools: Convert Machine Learning Models for On-Device Integration", https://coremltools.readme.io/

57. TensorFlow, "TensorFlow Lite: Machine Learning for Mobile and Edge", https://www.tensorflow.org/lite

58. Howard, A., Sandler, M., Chen, B., et al., "MobileNetV2: Inverted Residuals and Linear Bottlenecks", *CVPR 2018*, arXiv:1801.04381. https://arxiv.org/abs/1801.04381
## References

- "Machine Learning Engineering," Andriy Burkov, 2020.
- "Designing Machine Learning Systems," Huyen, C., O'Reilly, 2022.
- vLLM — Efficient LLM Serving. https://vllm.ai/
- TensorRT-LLM — NVIDIA. https://github.com/NVIDIA/TensorRT-LLM
- TGI — Text Generation Inference, HuggingFace. https://github.com/huggingface/text-generation-inference
- Triton Inference Server. https://github.com/triton-inference-server/server
- "ML Ops: Machine Learning Operations," various, Google Cloud. https://cloud.google.com/architecture/architecture-for-mlops
- LangServe — Deploy LangChain runnables. https://github.com/langchain-ai/langserve
- Kubernetes Documentation. https://kubernetes.io/docs/
- Prometheus Monitoring. https://prometheus.io/
- Grafana Dashboard. https://grafana.com/
- MLflow — ML Lifecycle Management. https://mlflow.org/
- Weights & Biases Documentation. https://docs.wandb.ai/
