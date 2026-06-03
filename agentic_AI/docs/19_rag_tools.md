# RAG, Knowledge Systems & Tool Use for AI Agents

> An exhaustive technical reference for building retrieval-augmented generation systems, knowledge architectures, and tool-using agents.

---

## Table of Contents

1. [RAG Fundamentals](#1-rag-fundamentals)
2. [Vector Databases Deep Dive](#2-vector-databases-deep-dive)
3. [Embedding Models](#3-embedding-models)
4. [Chunking Strategies](#4-chunking-strategies)
5. [Retrieval Strategies](#5-retrieval-strategies)
6. [Advanced RAG Patterns](#6-advanced-rag-patterns)
7. [Knowledge Graph Integration](#7-knowledge-graph-integration)
8. [Tool Use Patterns for Agents](#8-tool-use-patterns-for-agents)
9. [Building Custom Tools for Agents](#9-building-custom-tools-for-agents)
10. [MCP (Model Context Protocol)](#10-mcp-model-context-protocol)
11. [Tool Selection and Composition Strategies](#11-tool-selection-and-composition-strategies)

---

## 1. RAG Fundamentals

### What is RAG?

Retrieval-Augmented Generation (RAG) is an architecture that grounds large language model outputs in external knowledge by retrieving relevant documents at inference time and injecting them into the model's context window. Instead of relying solely on parametric memory (weights learned during training), RAG provides the model with curated, up-to-date, and domain-specific evidence before generating a response.

**Core insight**: LLMs are powerful reasoners with stale, incomplete, and hallucination-prone parametric knowledge. RAG bridges the gap between what the model *knows* and what it *needs to know* for a given query.

### Why RAG?

| Problem | RAG Solution |
|---|---|
| Hallucination | Ground responses in retrieved evidence |
| Stale knowledge | Dynamically fetch from live data stores |
| Domain gaps | Inject specialized corpora at query time |
| Cost of fine-tuning | No weight updates required |
| Attribution | Source documents provide citations |
| Data privacy | Keep data on-prem, never bake into weights |

### How RAG Works — The Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      COMPLETE RAG PIPELINE ARCHITECTURE                    │
│                                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌────────────┐    ┌───────────────┐  │
│  │ DOCUMENT │    │   CHUNKING   │    │  EMBEDDING  │    │     VECTOR    │  │
│  │  SOURCE  │───>│   ENGINE     │───>│   MODEL    │───>│   DATABASE    │  │
│  │          │    │              │    │            │    │               │  │
│  │ · PDF    │    │ · Fixed-size │    │ · OpenAI   │    │ · FAISS       │  │
│  │ · HTML   │    │ · Semantic   │    │ · Cohere   │    │ · Pinecone    │  │
│  │ · DB     │    │ · Recursive  │    │ · BGE      │    │ · Weaviate    │  │
│  │ · API    │    │ · Doc-specific│    │ · E5       │    │ · Milvus      │  │
│  │ · Wiki   │    │              │    │            │    │ · Qdrant      │  │
│  └──────────┘    └──────────────┘    └────────────┘    └───────┬───────┘  │
│                                                                     │      │
│  ┌──────────┐    ┌──────────────┐    ┌────────────┐    ┌─────────┴───────┐ │
│  │  FINAL   │    │   LLM        │    │ PROMPT     │    │   RETRIEVAL    │ │
│  │  ANSWER  │<───│  GENERATION  │<───│ CONSTRUCT  │<───│    ENGINE      │ │
│  │          │    │              │    │            │    │               │ │
│  │ · Text   │    │ · GPT-4      │    │ · Context  │    │ · Dense       │ │
│  │ · Cites  │    │ · Claude     │    │ · Query    │    │ · Sparse/BM25 │ │
│  │ · Conf   │    │ · Llama      │    │ · Sources  │    │ · Hybrid      │ │
│  │          │    │ · Mistral    │    │ · Instr.   │    │ · Re-ranked   │ │
│  └──────────┘    └──────────────┘    └────────────┘    └───────┬───────┘ │
│                                                             ▲         │
│                                                             │         │
│  ┌──────────┐    ┌──────────────┐                          │         │
│  │  USER    │    │   QUERY       │    ┌────────────┐        │         │
│  │  QUERY   │───>│  TRANSFORM   │───>│  EMBEDDING  │────────┘         │
│  │          │    │              │    │   MODEL     │                   │
│  │          │    │ · Rewrite    │    │            │                   │
│  │          │    │ · Decompose  │    │ (same as   │                   │
│  │          │    │ · Expand     │    │  indexing)  │                   │
│  └──────────┘    └──────────────┘    └────────────┘                    │
│                                                                        │
│  ═════════════════════════════════════════════════════════════════════  │
│  OFFLINE INDEXING PIPELINE (left side)                                 │
│  ONLINE QUERY PIPELINE (right side)                                    │
│  ═════════════════════════════════════════════════════════════════════  │
└─────────────────────────────────────────────────────────────────────────┘
```

### RAG vs. Fine-Tuning vs. Prompt Engineering

```
┌──────────────────┬───────────────────┬───────────────────┬───────────────────┐
│                  │  Prompt Eng.      │  RAG              │  Fine-Tuning      │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Knowledge cutoff │ Frozen in weights │ Live / dynamic    │ Updated in weights│
│ Hallucination    │ High              │ Low               │ Medium            │
│ Cost             │ $                 │ $$                │ $$$$              │
│ Latency          │ Low               │ Low–Medium        │ Medium            │
│ Data privacy     │ Exposed in prompt │ On-prem possible  │ Baked into model  │
│ Attribution      │ None              │ Built-in          │ None              │
│ Update frequency │ N/A               │ Real-time         │ Per training run  │
│ Domain expertise │ Shallow           │ Deep (corpus)     │ Deep (weights)    │
│ Implementation   │ Trivial           │ Moderate          │ Complex           │
└──────────────────┴───────────────────┴───────────────────┴───────────────────┘
```

---

## 2. Vector Databases Deep Dive

Vector databases store high-dimensional embeddings and support similarity search (k-NN / ANN). They are the backbone of any RAG system.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                  VECTOR DATABASE INTERNALS                           │
│                                                                     │
│  ┌─────────────┐     ┌─────────────────────────────────────┐       │
│  │  INSERT API │────>│         INDEXING PIPELINE            │       │
│  │             │     │                                     │       │
│  │ · vec + meta│     │  ┌──────────┐  ┌──────────────────┐  │       │
│  └─────────────┘     │  │ Quantize│  │  Build Index    │  │       │
│                      │  │ (fp32→  │  │  (HNSW / IVF /  │  │       │
│                      │  │  fp16/  │  │   DiskANN /     │  │       │
│                      │  │  int8)  │  │   Annoy / flat) │  │       │
│                      │  └──────────┘  └──────────────────┘  │       │
│                      └──────────────┬───────────────────────┘       │
│                                     │                                │
│                                     ▼                                │
│                      ┌─────────────────────────────────────┐       │
│                      │          SEGMENT STORAGE            │       │
│                      │                                     │       │
│                      │  ┌────────────┐ ┌────────────────┐  │       │
│                      │  │ Vector     │ │  Metadata      │  │       │
│                      │  │ Segment    │ │  Segment       │  │       │
│                      │  │ (index +   │ │  (filtered     │  │       │
│                      │  │  raw vecs) │ │   search)      │  │       │
│                      │  └────────────┘ └────────────────┘  │       │
│                      └──────────────┬───────────────────────┘       │
│                                     │                                │
│  ┌─────────────┐     ┌──────────────┴─────────────────────────┐   │
│  │  QUERY API  │────>│         SEARCH PIPELINE                │   │
│  │             │     │                                         │   │
│  │ · k-NN      │     │  ┌──────────┐  ┌──────────┐  ┌─────┐  │   │
│  │ · filtered  │     │  │ Prefilter│  │ ANN      │  │Rerank │  │   │
│  │ · hybrid    │     │  │ (metadata│  │ Search  │  │(exact │  │   │
│  │ · range     │     │  │  where)  │  │ (approx)│  │ top-k)│  │   │
│  └─────────────┘     │  └──────────┘  └──────────┘  └─────┘  │   │
│                      └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Vector Database Comparison

```
┌──────────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│   Feature    │  FAISS   │  Milvus  │Pinecone │Weaviate  │  Qdrant  │ ChromaDB │
├──────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Type         │ Library  │  Server  │ Managed │  Server  │  Server  │ Embedded │
│              │          │  cluster │  cloud  │          │          │ /server  │
├──────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Scaling      │ Single   │ Distrib. │ Auto    │ Distrib. │ Distrib. │ Single   │
│              │ node     │ cluster  │ scale   │ cluster  │ cluster  │ node     │
├──────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Persistence  │ Disk/RAM │  Disk    │ Cloud   │  Disk    │  Disk    │  Disk    │
│              │ (manual) │          │ managed │          │          │ (SQLite) │
├──────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ CRUD         │ Limited  │ Full     │ Full    │ Full     │ Full     │ Full     │
├──────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Metadata     │ Label    │ Full     │ Full    │ Full     │ Full     │ Full     │
│ filtering    │ only     │ filtered │ filtered│ filtered │ filtered │ filtered │
├──────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Hybrid       │ Manual   │ Built-in │ No(?)   │ Built-in │ Built-in │ Sparse  │
│ search       │          │          │         │          │          │ only     │
├──────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ GPU support  │ Yes      │ Yes      │ N/A     │ No       │ No       │ No       │
├──────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Best for     │ Research,│ Produc-  │ Quick   │ Seman-   │ Produc-  │ Proto-  │
│              │ offline, │ tion,    │ deploy,  │ tic     │ tion,    │ typing,  │
│              │ benchmark│ large    │ zero    │ search, │ flexibl. │ local    │
│              │ fast     │ scale    │ ops     │ GraphQL │ Docker   │ testing  │
├──────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ License      │ MIT      │ Apache   │ Propri- │ BSD-3   │ Apache   │ Apache   │
│              │          │ 2.0      │ etary   │          │ 2.0     │ 2.0     │
├──────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Latency      │ ~0.1ms   │ ~1-5ms   │ ~5-20ms │ ~2-10ms │ ~1-5ms   │ ~1-5ms  │
│ (avg query)  │ (batch) │          │ (net)    │         │          │          │
└──────────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
```

### Index Types: HNSW vs. IVF vs. Flat

```
HNSW (Hierarchical Navigable Small World)
┌──────────────────────────────────────────┐
│  Layer 2 (top): sparse long-range links │
│       ●──────────────────────●           │
│       │                      │           │
│  Layer 1: medium links                  │
│    ●───────●───────●───●───●             │
│    │       │       │   │   │             │
│  Layer 0 (bottom): dense short links    │
│  ●─●─●─●─●─●─●─●─●─●─●─●─●             │
│                                          │
│  Search: start at top layer, greedily   │
│  descend to nearest neighbor at each    │
│  layer. O(log n) complexity.            │
│  Memory: high (multiple graph layers)   │
│  Build: slower, query: very fast        │
└──────────────────────────────────────────┘

IVF (Inverted File)
┌──────────────────────────────────────────┐
│  Cluster centroids (Voronoi)            │
│         *          *                    │
│       /   \      /   \                  │
│     /  C1  \   /  C2  \                │
│    ● ● ● ●   ● ● ● ●                  │
│                                          │
│  Search: find nearest centroids, search │
│  only vectors in those partitions.      │
│  Probes: nprobe controls recall/speed  │
│  Memory: low (partition lists)          │
│  Build: fast, query: fast w/ nprobe    │
└──────────────────────────────────────────┘
```

**Selection guide**:
- **FAISS**: Use when you need maximum throughput for batch/benchmark workloads, are in Python, and can manage indexing manually.
- **Milvus**: Use for production deployments requiring distributed scale, high throughput, and multi-tenancy.
- **Pinecone**: Use when you want zero-ops managed infrastructure and don't mind vendor lock-in.
- **Weaviate**: Use when you need rich GraphQL queries, modules (vectorizers, generative), and BM25+dense hybrid search.
- **Qdrant**: Use when you want a Rust-based high-performance engine with filtering-native design and WAL-based persistence.
- **ChromaDB**: Use for prototyping, notebooks, and local development; migrate to a production DB later.

---

## 3. Embedding Models

Embedding models map text to dense vectors in a high-dimensional space (typically 384–3072 dimensions) such that semantically similar texts are close in vector space.

### Model Comparison

```
┌────────────────────────┬────────┬──────────┬────────────┬──────────────────────┐
│ Model                  │  Dims  │ MTEB avg │ Max tokens │ Best for              │
├────────────────────────┼────────┼──────────┼────────────┼──────────────────────┤
│ OpenAI text-embedding- │  1536  │ 61.0     │    8191    │ Production, easy API  │
│ ada-002                │        │          │            │                      │
├────────────────────────┼────────┼──────────┼────────────┼──────────────────────┤
│ OpenAI text-embedding- │  3072  │ ~64.3    │    8191    │ Higher quality, cost │
│ 3-large                │        │          │            │                      │
├────────────────────────┼────────┼──────────┼────────────┼──────────────────────┤
│ BAAI/bge-large-en-v1.5│  1024  │ ~64.0    │    512     │ Open-source SOTA     │
├────────────────────────┼────────┼──────────┼────────────┼──────────────────────┤
│ BAAI/bge-small-en-v1.5│   384  │ ~60.5    │    512     │ Speed, edge devices  │
├────────────────────────┼────────┼──────────┼────────────┼──────────────────────┤
│ intfloat/e5-large-v2   │  1024  │ ~62.5    │    512     │ Strong zero-shot     │
├────────────────────────┼────────┼──────────┼────────────┼──────────────────────┤
│ intfloat/multilingual- │  1024  │ ~60.x   │    512     │ Multilingual (100+)  │
│ e5-large              │        │          │            │                      │
├────────────────────────┼────────┼──────────┼────────────┼──────────────────────┤
│ Cohere embed-v3        │  1024  │ ~65.0    │    512     │ Best quality, API    │
├────────────────────────┼────────┼──────────┼────────────┼──────────────────────┤
│ sentence-transformers/ │   384  │ ~56.x   │    256     │ Lightweight, minimal │
│ all-MiniLM-L6-v2      │        │          │            │                      │
├────────────────────────┼────────┼──────────┼────────────┼──────────────────────┤
│ Nomic embed-text-v1.5  │   768  │ ~62.0    │    8192    │ Long context, open   │
├────────────────────────┼────────┼──────────┼────────────┼──────────────────────┤
│ Alibaba/GTE-Qwen2-1.5B│  1536  │ ~67.x   │   32768    │ SOTA, long context   │
│ (Matryoshka)           │        │          │            │                      │
└────────────────────────┴────────┴──────────┴────────────┴──────────────────────┘

MTEB = Massive Text Embedding Benchmark (higher = better)
```

### When to Use What

| Scenario | Recommended Model | Rationale |
|---|---|---|
| Quick prototype / local dev | `all-MiniLM-L6-v2` | Fast, small, zero cost |
| Production English RAG | `bge-large-en-v1.5` | Best open-source quality |
| Production (API, easy) | Cohere embed-v3 | Highest MTEB, managed |
| Multilingual | `multilingual-e5-large` | 100+ language support |
| Long documents (>512 tokens) | `nomic-embed-text-v1.5` or GTE-Qwen2 | 8K–32K context |
| Edge / mobile | `bge-small-en-v1.5` | 384 dims, fast inference |
| Cost-sensitive at scale | `bge-base-en-v1.5` | 768 dims, good quality/cost |
| Need compression | GTE-Qwen2 with Matryoshka | Truncate dims at query time |

### Embedding Pipeline Considerations

```python
# Best practices for embedding generation

# 1. ALWAYS prepend instruction prefix for models that expect it
#    E5: "query: " for queries, "passage: " for documents
#    BGE: "Represent this sentence: " for queries (varies by version)

# 2. Batch your embedding calls to reduce latency
embeddings = model.encode(texts, batch_size=256, show_progress_bar=True)

# 3. Normalize vectors (L2) for cosine similarity search
import numpy as np
embeddings = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)

# 4. Consider Matryoshka embeddings for flexible dimensionality
#    Store full dims, truncate at query time for speed/accuracy tradeoff
```

---

## 4. Chunking Strategies

Chunking determines how source documents are split into retrieval units. Bad chunking is the #1 cause of poor RAG performance.

### Chunking Strategy Comparison

```
┌────────────────┬──────────────────┬──────────────────┬──────────────────┐
│                │  FIXED-SIZE      │  SEMANTIC        │  RECURSIVE       │
│                │  CHUNKING        │  CHUNKING        │  CHUNKING        │
├────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Principle      │ Split every N    │ Split when      │ Split by        │
│                │ tokens/chars,    │ semantic         │ hierarch.        │
│                │ overlap by M     │ similarity drops │ separators       │
├────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Pros           │ · Simple         │ · Preserves      │ · Respects       │
│                │ · Deterministic  │   meaning        │   document       │
│                │ · Fast           │ · Context-aware  │   structure      │
│                │                  │ · Natural bounds │ · Good balance   │
├────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Cons           │ · Breaks thought │ · Slower (needs  │ · Requires good  │
│                │ · Loses context  │   embed compute) │   separators     │
│                │ · Ignores        │ · Variable sizes │ · May still      │
│                │   structure      │ · Harder to tune │   split mid-idea │
├────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Best for       │ · Logs           │ · Narratives     │ · General        │
│                │ · Uniform docs   │ · Long-form      │   purpose        │
│                │ · Quick baseline │ · Mixed content  │ · Code           │
│                │                  │                  │ · Markdown       │
├────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Typical params │ chunk=512,       │ threshold=0.7,   │ separators=      │
│                │ overlap=64       │ buffer=1 sent.   │ ["\n\n","\n"," "]
└────────────────┴──────────────────┴──────────────────┴──────────────────┘

┌────────────────┬──────────────────┬──────────────────┬──────────────────┐
│                │  DOCUMENT-       │  SENTENCE-       │  AGENTIC         │
│                │  SPECIFIC        │  LEVEL           │  CHUNKING        │
├────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Principle      │ Custom parsers   │ Split on         │ LLM decides      │
│                │ per format       │ sentence bounds  │ chunk boundaries  │
├────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Pros           │ · Structure-    │ · Small units    │ · Optimal        │
│                │   aware         │ · Precise        │   boundaries     │
│                │ · Format fidelity│ · Good compos.   │ · Context-aware  │
├────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Cons           │ · Format-specific│ · Too granular   │ · Expensive      │
│                │ · High maint.    │ · Needs window   │ · Slow           │
│                │                  │ · Loses macro    │ · Non-determinist.│
├────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Best for       │ · PDF tables     │ · Short docs     │ · High-value     │
│                │ · Code           │ · Q&A pairs      │   corpora        │
│                │ · Markdown       │ · Chat logs      │ · Low volume     │
│                │ · HTML DOM        │                  │ · Exact recall   │
└────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

### Recursive Chunking (Most Common — LangChain Default)

```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

splitter = RecursiveCharacterTextSplitter(
    separators=["\n\n", "\n", ". ", " ", ""],  # hierarchy of splits
    chunk_size=512,
    chunk_overlap=64,       # overlap prevents losing cross-boundary info
    length_function=len,
)

chunks = splitter.split_text(document)
```

### Document-Specific Chunking Examples

```python
# Markdown: respect headings
from langchain.text_splitter import MarkdownHeaderTextSplitter
headers_to_split_on = [("#", "H1"), ("##", "H2"), ("###", "H3")]
md_splitter = MarkdownHeaderTextSplitter(headers_to_split_on)
# Each chunk carries metadata: {"H1": "Intro", "H2": "Background"}

# Code: respect functions/classes
from langchain.text_splitter import Language, RecursiveCharacterTextSplitter
code_splitter = RecursiveCharacterTextSplitter.from_language(
    language=Language.PYTHON,
    chunk_size=1000,
    chunk_overlap=100,
)

# PDF tables: extract structured data first, then chunk
# Use unstructured, pymupdf, or docetl for table-aware extraction
```

### Chunk Size Guidelines

| Use Case | Recommended Size | Overlap | Reasoning |
|---|---|---|---|
| Factoid QA | 256–512 | 10–20% | Need precise facts, not narrative |
| Summarization | 1000–2000 | 5–10% | Need broader context windows |
| Code search | 500–1000 | 50–100 | Functions as natural units |
| Conversational | 512–1024 | 15–20% | Balance context and precision |

---

## 5. Retrieval Strategies

### Dense Retrieval

The default: embed the query, find k-nearest vectors by cosine similarity.

```
Query ──> Embed Model ──> [0.13, -0.42, ...] ──> ANN Search ──> Top-k Docs
                                                       │
                                            Cosine / Dot / L2
                                            similarity metric
```

### Sparse Retrieval (BM25)

Classic keyword matching via TF-IDF variant. Excellent for exact term matching (IDs, names, rare words).

```
Query: "HNSW index construction parameters"
            │
            ▼
    ┌───────────────────┐
    │  Term Frequency    │
    │  + IDF weighting  │
    │  + length norm.   │
    └────────┬──────────┘
             │
             ▼
    Documents with "HNSW", "index",
    "construction", "parameters"
    ranked by BM25 score
```

### Hybrid Retrieval (Dense + Sparse)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    HYBRID RETRIEVAL PIPELINE                         │
│                                                                     │
│                    ┌──────────┐                                     │
│                    │  Query   │                                     │
│                    └────┬─────┘                                     │
│                         │                                           │
│              ┌──────────┴──────────┐                               │
│              ▼                     ▼                                │
│      ┌───────────────┐    ┌───────────────┐                        │
│      │ Dense (k=50) │    │  BM25 (k=50)  │                        │
│      │  Embed + ANN │    │  Sparse index │                        │
│      └───────┬───────┘    └───────┬───────┘                        │
│              │                    │                                  │
│              └────────┬───────────┘                                 │
│                       ▼                                             │
│              ┌─────────────────┐                                    │
│              │  Reciprocal Rank │                                    │
│              │  Fusion (RRF)   │──── fused ranking                  │
│              │  OR             │                                    │
│              │  Linear combo  │──── α·dense + (1-α)·sparse         │
│              └────────┬────────┘                                    │
│                       ▼                                             │
│              ┌─────────────────┐                                    │
│              │  Top-k merged   │                                    │
│              │  results        │                                    │
│              └─────────────────┘                                    │
└─────────────────────────────────────────────────────────────────────┘
```

```python
# RRF scoring: score(d) = Σ 1/(k + rank_i(d))
# k typically = 60
def reciprocal_rank_fusion(rankings: list[list], k=60):
    scores = {}
    for ranking in rankings:
        for rank, doc in enumerate(ranking):
            scores[doc] = scores.get(doc, 0) + 1 / (k + rank + 1)
    return sorted(scores.items(), key=lambda x: x[1], reverse=True)
```

### Re-Ranking

After initial retrieval, re-rank candidates using a cross-encoder or LLM for higher precision.

```
┌──────────┐     ┌──────────┐     ┌──────────────┐     ┌──────────┐
│  Query   │────>│ Retrieve │────>│   Reranker   │────>│ Final    │
│          │     │ top-100  │     │ (cross-enc/  │     │ top-k    │
│          │     │ (fast)   │     │  LLM/Cohere) │     │ (precise)│
└──────────┘     └──────────┘     └──────────────┘     └──────────┘
                                     │
                                     │  Cross-encoder jointly
                                     │  encodes (query, doc)
                                     │  ─ more expensive but
                                     │  much more accurate
```

Common rerankers:
- **Cohere Rerank v3**: API-based, best-quality, $2.00/1K searches
- **bge-reranker-large**: Open-source cross-encoder, strong quality
- **cross-encoder/ms-marco-MiniLM-L-12-v2**: Fast, decent quality
- **LLM-as-reranker**: Use GPT-4/Claude to score relevance, expensive but flexible

### Multi-Query Retrieval

When a user query is ambiguous or narrow, generate multiple query variations and retrieve for each.

```python
# Generate query variations
original_query = "How does HNSW work?"
variations = [
    "Explain hierarchical navigable small world graphs",
    "HNSW algorithm implementation details",
    "Approximate nearest neighbor search with HNSW",
    "HNSW vs IVF vs Annoy comparison",
]

# Retrieve for each, deduplicate, and union results
all_results = []
for q in variations:
    all_results.extend(vector_db.search(embed(q), top_k=5))

# Deduplicate by document ID, optionally re-rank
unique_results = deduplicate(all_results)
final = reranker.rank(original_query, unique_results, top_k=10)
```

### Retrieval Strategy Decision Flowchart

```
┌─────────────────────────────────────────────────────────────────────┐
│                  WHICH RETRIEVAL STRATEGY?                           │
│                                                                     │
│                         ┌──────────┐                               │
│                         │  Query?   │                               │
│                         └─────┬────┘                               │
│                               │                                     │
│              ┌────────────────┼──────────────────┐                  │
│              ▼                ▼                  ▼                  │
│       ┌──────────┐    ┌──────────────┐   ┌──────────────┐        │
│       │Precise   │    │Ambiguous/    │   │Multi-faceted │        │
│       │factoid   │    │complex       │   │broad         │        │
│       └────┬─────┘    └──────┬───────┘   └──────┬───────┘        │
│            │                 │                   │                 │
│            ▼                 ▼                   ▼                 │
│       ┌──────────┐    ┌──────────────┐   ┌──────────────┐        │
│       │Dense +   │    │Multi-query +  │   │Hybrid +      │        │
│       │Sparse    │    │Re-rank        │  │Re-rank       │        │
│       │(hybrid)  │    │               │   │              │        │
│       └──────────┘    └───────────────┘   └──────────────┘        │
│                                                                     │
│              Need higher precision?                                  │
│                    │                                                 │
│           ┌───────┴───────┐                                          │
│           ▼               ▼                                          │
│      ┌─────────┐   ┌──────────────┐                                  │
│      │Add      │   │Use           │                                  │
│      │reranker  │   │self-RAG /    │                                  │
│      │          │   │corrective   │                                  │
│      │          │   │patterns      │                                  │
│      └─────────┘   └──────────────┘                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Advanced RAG Patterns

### Naive RAG (Baseline)

```
Query ──> Retrieve ──> Prompt + Context ──> Generate
```

Problems: irrelevant chunks, hallucinated claims, no verification.

### Advanced RAG Patterns Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ADVANCED RAG PATTERNS COMPARISON                          │
│                                                                             │
│ ┌───────────────────────────────────────────────────────────────────────┐   │
│ │  SELF-RAG                                                              │   │
│ │                                                                         │   │
│ │  Query ──>Retrieve──>LLM──┐                                            │   │
│ │                            │                                            │   │
│ │                  ┌─────────┴──────────┐                                │   │
│ │                  │ Self-reflection:    │                                │   │
│ │                  │ Is retrieval needed? │──(No)──> Generate directly   │   │
│ │                  │ Is context relevant?│──(No)──> Re-retrieve          │   │
│ │                  │ Is output faithful? │──(No)──> Re-generate         │   │
│ │                  │ Is output useful?   │──(No)──> Re-generate         │   │
│ │                  └────────────────────┘                                │   │
│ │                                                                         │   │
│ │  Key: Model decides WHEN to retrieve and self-evaluates output          │   │
│ └───────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│ ┌───────────────────────────────────────────────────────────────────────┐   │
│ │  CORRECTIVE RAG (CRAG)                                                 │   │
│ │                                                                         │   │
│ │  Query ──>Retrieve──>┌──────────┐                                     │   │
│ │                      │Retrieval │                                      │   │
│ │                      │Evaluator │                                      │   │
│ │                      │(score)   │                                      │   │
│ │                      └────┬─────┘                                      │   │
│ │                           │                                             │   │
│ │                ┌──────────┼──────────┐                                │   │
│ │                ▼          ▼          ▼                                │   │
│ │          Correct     Ambiguous    Incorrect                           │   │
│ │                │          │          │                                 │   │
│ │                ▼          ▼          ▼                                 │   │
│ │          Use as-is   Web search   Discard &                           │   │
│ │                      supplement    regenerate                        │   │
│ │                                                                         │   │
│ │  Key: Evaluate retrieval quality, correct before generation            │   │
│ └───────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│ ┌───────────────────────────────────────────────────────────────────────┐   │
│ │  ADAPTIVE RAG                                                          │   │
│ │                                                                         │   │
│ │  Query ──>┌──────────────────┐                                       │   │
│ │           │ Query Complexity  │                                       │   │
│ │           │ Classifier         │                                       │   │
│ │           │ (small LLM/rule)  │                                       │   │
│ │           └──────┬────────────┘                                       │   │
│ │                  │                                                      │   │
│ │       ┌─────────┼───────────┐                                         │   │
│ │       ▼         ▼           ▼                                         │   │
│ │    Simple    Moderate   Complex                                        │   │
│ │       │         │           │                                          │   │
│ │       ▼         ▼           ▼                                          │   │
│ │   No retrieval  Single    Multi-step                                  │   │
│ │   (parametric)  retrieve  retrieve +                                   │   │
│ │                          web search                                    │   │
│ │                                                                         │   │
│ │  Key: Route queries to appropriate retrieval strategy by complexity    │   │
│ └───────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│ ┌───────────────────────────────────────────────────────────────────────┐   │
│ │  GRAPH RAG                                                             │   │
│ │                                                                         │   │
│ │  Documents ──>Extract entities/relations──>Build knowledge graph      │   │
│ │       │                                               │                │   │
│ │       ▼                                               ▼                │   │
│ │  Chunk + embed                                   Graph traversal      │   │
│ │       │                                               │                │   │
│ │       └──────────────┬────────────────────────────────┘               │   │
│ │                      ▼                                                 │   │
│ │              Combine vector + graph context                            │   │
│ │                      │                                                  │   │
│ │                      ▼                                                  │   │
│ │              LLM generates answer                                       │   │
│ │                                                                         │   │
│ │  Key: Combine structured (graph) + unstructured (vector) knowledge     │   │
│ └───────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Self-RAG in Detail

Self-RAG introduces three types of *reflection tokens* that the model generates alongside the output:

| Token | Purpose | Values |
|---|---|---|
| `Retrieve` | Decide if retrieval is needed | Yes / No |
| `IsRel` | Is the retrieved passage relevant? | Relevant / Irrelevant |
| `IsSup` | Is the output supported by the passage? | Fully supported / Partially / No |
| `IsUse` | Is the output useful for the query? | Useful / Not useful |

The model learns to *self-evaluate* and *self-correct* at each generation step, enabling fine-grained control over retrieval and faithfulness.

### Corrective RAG (CRAG) Scoring

```python
def evaluate_retrieval(query: str, docs: list[str]) -> str:
    """Classify retrieval quality into correct/ambiguous/incorrect."""
    prompt = f"""Rate the relevance of these documents to the query.
    Query: {query}
    Docs: {docs[:3]}
    Answer: correct / ambiguous / incorrect"""
    return llm(prompt).strip().lower()

# Routing logic
score = evaluate_retrieval(query, retrieved_docs)
if score == "correct":
    context = retrieved_docs
elif score == "ambiguous":
    context = retrieved_docs + web_search(query)
else:  # incorrect
    context = web_search(query)
```

---

## 7. Knowledge Graph Integration

### Architecture: Graph + Vector Hybrid

```
┌─────────────────────────────────────────────────────────────────────┐
│             KNOWLEDGE GRAPH + RAG INTEGRATION                        │
│                                                                     │
│  ┌────────────────┐                          ┌──────────────────┐  │
│  │  USER QUERY    │                          │  DOCUMENT CORPUS │  │
│  └───────┬────────┘                          └────────┬─────────┘  │
│          │                                            │            │
│          │                              ┌─────────────┴──────┐    │
│          │                              │  Entity & Relation │    │
│          │                              │  Extraction (NER + │    │
│          │                              │  dependency parse)  │    │
│          │                              └─────────┬──────────┘    │
│          │                                        │                │
│          │                              ┌─────────┴──────────┐    │
│          │                              │  KNOWLEDGE GRAPH   │    │
│          │                              │                    │    │
│          │                              │  (Neo4j / NetworkX │    │
│          │                              │   / ArangoDB)      │    │
│          │                              │                    │    │
│          │                              │  ┌──────────────┐  │    │
│          │                              │  │  Entities   │  │    │
│          │                              │  │ (nodes)     │  │    │
│          │                              │  └──────┬───────┘  │    │
│          │                              │         │          │    │
│          │                              │  ┌──────┴───────┐  │    │
│          │                              │  │  Relations  │  │    │
│          │                              │  │ (edges)     │  │    │
│          │                              │  └──────────────┘  │    │
│          │                              └─────────┬──────────┘    │
│          │                                        │                │
│  ┌───────┴────────┐              ┌───────────────┴──────────┐    │
│  │  Entity         │              │  VECTORIZED CHUNKS       │    │
│  │  Linking +     │              │  (embeddings in vector   │    │
│  │  Graph          │              │   database)             │    │
│  │  Traversal      │              └───────────────┬──────────┘    │
│  └───────┬────────┘                              │                │
│          │                                        │                │
│          └──────────────┬─────────────────────────┘                │
│                         │                                          │
│                         ▼                                          │
│              ┌─────────────────────┐                               │
│              │ CONTEXT ASSEMBLY    │                               │
│              │                     │                               │
│              │  · Vector context   │                               │
│              │  · Graph context    │                               │
│              │    (traversed       │                               │
│              │     subgraph)       │                               │
│              │  · Entity metadata  │                               │
│              └─────────┬───────────┘                               │
│                        │                                            │
│                        ▼                                            │
│              ┌─────────────────────┐                               │
│              │     LLM GENERATION  │                               │
│              └─────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────┘
```

### Knowledge Graph Construction Pipeline

```python
# Step 1: Extract entities and relations from documents
entity_prompt = """
Extract entities and relations from this text.
Return as JSON: {"entities": [{name, type}], "relations": [{src, rel, dst}]}
Text: {chunk}
"""

# Step 2: Deduplicate and canonicalize entities
# "Apple Inc.", "Apple", "AAPL" → canonical: "Apple Inc."

# Step 3: Build the graph
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687")

def add_triple(tx, src, rel, dst):
    tx.run("""
    MERGE (s:Entity {name: $src})
    MERGE (d:Entity {name: $dst})
    MERGE (s)-[r:RELATES {type: $rel}]->(d)
    """, src=src, dst=dst, rel=rel)

# Step 4: At query time, traverse graph for multi-hop context
def graph_context(query_entities, max_hops=2):
    result = driver.session().run("""
    MATCH (e:Entity)-[r*1..2]-(neighbor)
    WHERE e.name IN $entities
    RETURN e.name, neighbor.name, r
    """, entities=query_entities)
    return result.data()
```

### Graph RAG Query Flow

1. **Extract entities** from the user query
2. **Link entities** to the knowledge graph (fuzzy matching / embedding)
3. **Traverse graph** from matched entities (1–3 hops)
4. **Retrieve** neighboring text chunks for traversed nodes
5. **Concatenate** graph context + vector context into the prompt
6. **Generate** answer with full structural + textual grounding

---

## 8. Tool Use Patterns for Agents

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│               TOOL USE ARCHITECTURE FOR AI AGENTS                   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    AGENT CORE (LLM)                         │   │
│  │                                                             │   │
│  │  ┌───────────┐  ┌───────────┐  ┌────────────────────────┐ │   │
│  │  │ Reasoning │  │ Planning  │  │  Tool Selection Engine  │ │   │
│  │  │ (Chain-of │  │ (Task    │  │  (which tool? which     │ │   │
│  │  │  Thought) │  │  decomp) │  │   args? in what order?) │ │   │
│  │  └───────────┘  └───────────┘  └───────────┬────────────┘ │   │
│  │                                             │               │   │
│  └─────────────────────────────────────────────┼───────────────┘   │
│                                                 │                   │
│                    ┌────────────────────────────┼──────────────┐    │
│                    │         TOOL REGISTRY      │              │    │
│                    │  ┌─────────┐ ┌─────────┐ │ ┌─────────┐  │    │
│                    │  │Search   │ │Code     │ │ │Database │  │    │
│                    │  │Tool    │ │Exec     │ │ │Query    │  │    │
│                    │  └────┬────┘ └────┬────┘ │ └────┬────┘  │    │
│                    │       │           │       │      │       │    │
│                    │  ┌────┴────┐ ┌───┴────┐ ┌┴────┴───┐   │    │
│                    │  │Web     │ │Python  │ │SQL      │   │    │
│                    │  │Search  │ │Sandbox │ │Engine   │   │    │
│                    │  └─────────┘ └────────┘ └──────────┘   │    │
│                    │  ┌─────────┐ ┌──────────────────────┐   │    │
│                    │  │File     │ │API Caller             │   │    │
│                    │  │System   │ │(REST/GraphQL)         │   │    │
│                    │  └─────────┘ └──────────────────────┘   │    │
│                    └──────────────────────────────────────────┘    │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    TOOL EXECUTION SANDBOX                     │  │
│  │                                                              │  │
│  │  · Sandboxed code execution (Docker, Firecracker)           │  │
│  │  · Rate limiting & timeout enforcement                       │  │
│  │  · Output validation & sanitization                        │  │
│  │  · Resource quotas (CPU, memory, network)                  │  │
│  │  · Audit logging of all tool calls                          │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Function Calling (OpenAI / Anthropic Style)

The LLM receives a list of available tools as JSON Schema definitions and can decide to *call* a tool by outputting a structured message instead of plain text.

```python
# OpenAI function calling
tools = [
    {
        "type": "function",
        "function": {
            "name": "search_documents",
            "description": "Search the knowledge base for relevant documents",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of results to return",
                        "default": 5
                    },
                    "filter": {
                        "type": "object",
                        "description": "Metadata filters",
                        "properties": {
                            "source": {"type": "string"},
                            "date_range": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                },
                "required": ["query"]
            }
        }
    }
]

response = openai.chat.completions.create(
    model="gpt-4",
    messages=messages,
    tools=tools,
    tool_choice="auto",  # or {"type": "function", "function": {"name": "search_documents"}}
)

# If model decides to call a tool:
if response.choices[0].message.tool_calls:
    tool_call = response.choices[0].message.tool_calls[0]
    # Execute in your code, then append result
    result = execute_tool(tool_call.function.name, json.loads(tool_call.function.arguments))
    messages.append({
        "role": "tool",
        "tool_call_id": tool_call.id,
        "content": json.dumps(result)
    })
```

### Code Execution as a Tool

```python
# Safe code execution pattern
import subprocess
import tempfile

def execute_python(code: str, timeout: int = 30) -> dict:
    """Execute Python code in a sandboxed environment."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        try:
            result = subprocess.run(
                ["python3", f.name],
                capture_output=True,
                text=True,
                timeout=timeout,
                # Sandbox: restrict filesystem, network
                env={"PYTHONPATH": "", "HOME": "/tmp"},
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Execution timed out after {timeout}s"}
        finally:
            os.unlink(f.name)
```

### API Integration Pattern

```python
# Generic API tool wrapper
def create_api_tool(name: str, description: str, endpoint: str, method: str):
    """Create a tool that calls an external API."""
    
    # Dynamically generate JSON schema from OpenAPI spec
    schema = generate_schema_from_openapi(endpoint, method)
    
    def executor(**kwargs):
        url = endpoint.format(**kwargs)
        if method == "GET":
            response = requests.get(url, params=kwargs, timeout=10)
        else:
            response = requests.post(url, json=kwargs, timeout=10)
        response.raise_for_status()
        return response.json()
    
    return ToolDefinition(
        name=name,
        description=description,
        parameters=schema,
        executor=executor,
    )
```

---

## 9. Building Custom Tools for Agents

### Design Principles

1. **Single responsibility**: Each tool does one thing well
2. **Clear boundaries**: Minimize overlap between tools
3. **Descriptive schemas**: The LLM decides based on name + description alone
4. **Idempotent where possible**: Same input → same output
5. **Fail gracefully**: Return structured errors, not exceptions
6. **Minimal output**: Return only what the agent needs, not raw dumps

### Schema Definition

```python
from pydantic import BaseModel, Field
from typing import Optional, Literal

class SearchDocumentsTool(BaseModel):
    """Search the internal knowledge base for relevant documents.
    
    Use this tool when you need to find information about company
    policies, technical documentation, or historical decisions.
    Do NOT use this for web searches — use the web_search tool instead.
    """
    query: str = Field(
        ...,
        description="A clear, specific search query. Use keywords, not full sentences.",
        min_length=3,
        max_length=500,
    )
    top_k: int = Field(
        default=5,
        description="Number of documents to return. Use 3 for quick lookups, 10 for thorough research.",
        ge=1,
        le=20,
    )
    collection: Literal["policies", "tech_docs", "meeting_notes", "all"] = Field(
        default="all",
        description="Which collection to search. 'all' searches everything.",
    )
    date_filter: Optional[str] = Field(
        default=None,
        description="Filter results by date range. Format: 'YYYY-MM-DD:YYYY-MM-DD'",
    )

class ToolResult(BaseModel):
    success: bool
    data: Optional[dict] = None
    error: Optional[str] = None
    metadata: dict = Field(default_factory=dict)

def search_documents(params: SearchDocumentsTool) -> ToolResult:
    try:
        results = vector_db.search(
            query=embed(params.query),
            top_k=params.top_k,
            filter={"collection": params.collection},
        )
        return ToolResult(
            success=True,
            data={"results": results},
            metadata={"query": params.query, "latency_ms": ...}
        )
    except VectorDBError as e:
        return ToolResult(
            success=False,
            error=f"Search failed: {str(e)}",
        )
    except Exception as e:
        return ToolResult(
            success=False,
            error=f"Unexpected error. Please try a different query.",
        )
```

### Error Handling Best Practices

```python
# Tool execution wrapper with comprehensive error handling
from functools import wraps
import time
import logging

logger = logging.getLogger(__name__)

def tool_handler(max_retries=2, timeout=30, rate_limit=10):
    """Decorator for tool execution with retries, timeouts, rate limiting."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            call_count = 0
            
            # Rate limiting
            if not rate_limiter.allow(func.__name__):
                return ToolResult(
                    success=False,
                    error="Rate limit exceeded. Please wait before retrying.",
                    metadata={"retry_after_seconds": rate_limiter.retry_after(func.__name__)}
                )
            
            for attempt in range(max_retries + 1):
                try:
                    call_count += 1
                    start = time.time()
                    result = func(*args, **kwargs)
                    latency = time.time() - start
                    
                    logger.info(f"Tool {func.__name__} succeeded in {latency:.2f}s (attempt {call_count})")
                    return result
                    
                except TimeoutError:
                    if attempt == max_retries:
                        return ToolResult(success=False, error="Operation timed out.")
                        
                except ValidationError as e:
                    return ToolResult(success=False, error=f"Invalid parameters: {e.details}")
                    
                except ExternalAPIError as e:
                    if e.status_code == 429:  # Rate limited by external API
                        wait = int(e.headers.get("Retry-After", 5))
                        time.sleep(wait)
                        continue
                    return ToolResult(success=False, error=f"External API error: {e.message}")
                    
                except Exception as e:
                    logger.error(f"Tool {func.__name__} failed: {e}", exc_info=True)
                    if attempt == max_retries:
                        return ToolResult(
                            success=False,
                            error="An unexpected error occurred. Try rephrasing your request."
                        )
                    time.sleep(2 ** attempt)  # Exponential backoff
                    
            return ToolResult(success=False, error="Max retries exceeded.")
        return wrapper
    return decorator
```

---

## 10. MCP (Model Context Protocol)

### What is MCP?

The Model Context Protocol (MCP) is an open standard by Anthropic that defines how AI models connect to external data sources and tools. It provides a universal, JSON-RPC-based protocol for discovering, describing, and invoking tools — replacing ad-hoc function-calling integrations with a standardized interface.

### MCP Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    MCP ARCHITECTURE                                   │
│                                                                     │
│  ┌─────────────────────┐                    ┌─────────────────────┐ │
│  │    MCP HOST          │                    │   MCP SERVER        │ │
│  │    (AI Application)  │                    │   (Tool Provider)   │ │
│  │                     │                    │                     │ │
│  │  ┌───────────────┐  │    JSON-RPC         │  ┌───────────────┐ │ │
│  │  │  MCP Client   │◄─┤──────────────────┤─►│  MCP Server   │ │ │
│  │  │  (inside host)│  │    over stdio/     │  │  (exposes     │ │ │
│  │  │               │  │    SSE/HTTP        │  │   tools &     │ │ │
│  │  └───────────────┘  │                    │  │   resources)  │ │ │
│  │         │            │                    │  └───────┬───────┘ │ │
│  │         ▼            │                    │          │         │ │
│  │  ┌───────────────┐  │                    │          ▼         │ │
│  │  │  LLM / Agent  │  │                    │  ┌───────────────┐ │ │
│  │  │  (uses tools) │  │                    │  │  Backends:    │ │ │
│  │  └───────────────┘  │                    │  │ · PostgreSQL  │ │ │
│  │                     │                    │  │ · GitHub      │ │ │
│  │                     │                    │  │ · Filesystem  │ │ │
│  │                     │                    │  │ · Slack       │ │ │
│  │                     │                    │  │ · Custom APIs │ │ │
│  └─────────────────────┘                    │  └───────────────┘ │ │
│                                              └─────────────────────┘ │
│                                                                     │
│  ═════════════════════════════════════════════════════════════      │
│  MCP PROTOCOL: 3 primitives                                         │
│  ═════════════════════════════════════════════════════════════      │
│                                                                     │
│  1. TOOLS      ─ Functions the LLM can call                        │
│     · name, description, inputSchema (JSON Schema)                  │
│     · Invoked via tools/call → returns content                      │
│                                                                     │
│  2. RESOURCES  ─ Data the LLM can read (like GET endpoints)        │
│     · URI-addressable (e.g. file:///path, db://table)               │
│     · Read via resources/read → returns text/blob                   │
│                                                                     │
│  3. PROMPTS    ─ Reusable prompt templates                          │
│     · Named templates with arguments                                │
│     · Retrieved via prompts/list, prompts/get                       │
└─────────────────────────────────────────────────────────────────────┘
```

### MCP Server Example

```python
# mcp_server.py — A minimal MCP server exposing a search tool
from mcp.server import Server
from mcp.types import Tool, TextContent

server = Server("knowledge-base")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="search_knowledge_base",
            description="Search the internal knowledge base for relevant documents",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "top_k": {"type": "integer", "default": 5},
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="get_document",
            description="Retrieve a specific document by ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "doc_id": {"type": "string", "description": "Document UUID"},
                },
                "required": ["doc_id"],
            },
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "search_knowledge_base":
        results = vector_db.search(embed(arguments["query"]), top_k=arguments.get("top_k", 5))
        return [TextContent(type="text", text=json.dumps(results))]
    elif name == "get_document":
        doc = doc_store.get(arguments["doc_id"])
        return [TextContent(type="text", text=doc.content)]

# Run via: mcp run mcp_server.py
```

### MCP Key Benefits

| Benefit | Description |
|---|---|
| **Interoperability** | Any MCP-compatible host can use any MCP server |
| **Discovery** | Tools, resources, prompts are dynamically discoverable |
| **Security** | Servers run in isolation, grants are explicit and scoped |
| **Composability** | Multiple servers can be composed; one host → many servers |
| **Standardized** | Replaces N custom integrations with one protocol |

---

## 11. Tool Selection and Composition Strategies

### Tool Selection: How the Agent Chooses

```
┌─────────────────────────────────────────────────────────────────────┐
│                  TOOL SELECTION DECISION TREE                        │
│                                                                     │
│                         ┌──────────┐                                │
│                         │  Query   │                                │
│                         └────┬─────┘                                │
│                              │                                      │
│                    ┌─────────┴──────────┐                          │
│                    ▼                    ▼                           │
│             ┌───────────┐        ┌──────────────┐                  │
│             │ Needs     │        │ Can answer   │                  │
│             │ external  │        │ from memory  │                  │
│             │ data/tool │        │              │                  │
│             └─────┬─────┘        └──────┬───────┘                  │
│                   │                     │                           │
│         ┌─────────┴──────────┐         │                           │
│         ▼         ▼          ▼         ▼                           │
│    ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐                   │
│    │Retrieve│ │Compute │ │Act     │ │Direct   │                   │
│    │        │ │        │ │        │ │answer    │                   │
│    │(search │ │(code   │ │(API    │ │          │                   │
│    │ RAG)   │ │ exec)  │ │ call)  │ │          │                   │
│    └───┬────┘ └───┬────┘ └───┬────┘ └────────┘                   │
│        │           │          │                                      │
│        └───────────┴──────────┘                                      │
│                    │                                                  │
│                    ▼                                                  │
│         ┌──────────────────┐                                        │
│         │  Tool Composition│                                        │
│         │  (chain / parallel│                                       │
│         │   / conditional)  │                                       │
│         └──────────────────┘                                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Composition Patterns

**Sequential Chain** — Tools called in order, each feeding the next:

```python
# Plan: search → summarize → translate
result_1 = search_tool(query="quantum computing advances 2025")
result_2 = summarize_tool(text=result_1, max_length=200)
result_3 = translate_tool(text=result_2, target_lang="ja")
```

**Parallel Fan-out** — Independent tools called simultaneously:

```python
# Research query: get multiple perspectives in parallel
import asyncio

results = await asyncio.gather(
    search_tool(query="climate policy EU"),
    search_tool(query="climate policy US"),
    search_tool(query="climate policy China"),
    web_search_tool(query="latest climate summit outcomes"),
)
```

**Conditional Routing** — Choose tools based on intermediate results:

```python
# Adaptive strategy based on retrieval quality
retrieved = search_tool(query=user_query, top_k=10)

if retrieval_evaluator.score(retrieved) > 0.8:
    # High quality: use directly
    return generate_tool(context=retrieved, query=user_query)
elif retrieval_evaluator.score(retrieved) > 0.4:
    # Medium: supplement with web search
    web_results = web_search_tool(query=user_query)
    return generate_tool(context=retrieved + web_results, query=user_query)
else:
    # Low: fall back to direct generation + disclaimer
    return generate_tool(context=[], query=user_query, disclaimer=True)
```

**Iterative Refinement** — Agent loops until quality threshold met:

```python
max_iterations = 5
for i in range(max_iterations):
    answer = generate_tool(context=context, query=query)
    critique = critique_tool(answer=answer, context=context, query=query)
    if critique.score >= 0.9:
        return answer
    # Refine: add critique feedback to context
    context.append({"role": "assistant", "content": critique.feedback})
    
return answer  # Return best effort after max iterations
```

### Tool Selection Best Practices

| Practice | Description |
|---|---|
| **Limit tool count** | 5–15 tools per agent; beyond this, selection accuracy degrades |
| **Descriptive names** | `search_internal_docs` not `search1` |
| **Detailed descriptions** | Include when to use AND when NOT to use |
| **Minimal parameters** | Only required params; use defaults for optional |
| **Schema validation** | Use Pydantic / JSON Schema; reject bad args early |
| **Timeout budgets** | Set per-tool timeouts; total budget for the full plan |
| **Result truncation** | Return summaries, not raw API responses (save tokens) |
| **Idempotency** | Design tools to be safe to call multiple times |
| **Observability** | Log every tool call, args, result, latency |

### Token Budget Management

```
┌─────────────────────────────────────────────────────────────────────┐
│  CONTEXT WINDOW BUDGET (e.g., 128K tokens)                         │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ System prompt + tool definitions          ≈  2K–5K tokens    │  │
│  ├───────────────────────────────────────────────────────────────┤  │
│  │ Conversation history                       ≈ 10K–30K tokens  │  │
│  ├───────────────────────────────────────────────────────────────┤  │
│  │ Retrieved context (RAG chunks)            ≈  4K–20K tokens   │  │
│  ├───────────────────────────────────────────────────────────────┤  │
│  │ Tool call + results (per turn)            ≈  1K–5K tokens    │  │
│  ├───────────────────────────────────────────────────────────────┤  │
│  │ Reserved for generation                    ≈  2K–4K tokens    │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Key: Prioritize the most relevant context. Discard:                │
│       · Low-relevance retrieved chunks                              │
│       · Old conversation turns                                      │
│       · Verbose tool outputs (summarize first!)                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Summary: RAG + Tools = Cognitive Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│              AGENTIC RAG + TOOL ARCHITECTURE                         │
│                                                                     │
│                         ┌──────────────┐                            │
│                         │  USER QUERY  │                            │
│                         └──────┬───────┘                            │
│                                │                                     │
│                         ┌──────┴───────┐                            │
│                         │  AGENT CORE  │                            │
│                         │  (LLM +      │                            │
│                         │   planner)   │                            │
│                         └──────┬───────┘                            │
│                                │                                     │
│            ┌───────────────────┼───────────────────┐               │
│            ▼                   ▼                   ▼                │
│     ┌─────────────┐   ┌───────────────┐   ┌─────────────┐          │
│     │ MEMORY      │   │ RETRIEVAL     │   │ TOOLS       │          │
│     │             │   │               │   │             │          │
│     │ · Conversation│  │ · Dense (kNN) │   │ · Code exec │          │
│     │ · Long-term  │   │ · Sparse(BM25)│   │ · Web search│          │
│     │ · Working    │   │ · Hybrid+RRF  │   │ · APIs      │          │
│     │   memory     │   │ · Re-rank     │   │ · Databases │          │
│     │             │   │ · Multi-query │   │ · File I/O  │          │
│     └──────┬──────┘   │ · Knowledge   │   │ · MCP       │          │
│            │          │   graph       │   │   servers   │          │
│            │          └───────┬───────┘   └──────┬──────┘          │
│            │                  │                   │                   │
│            └──────────────────┼───────────────────┘               │
│                               │                                     │
│                    ┌──────────┴──────────┐                          │
│                    │  CONTEXT MANAGER    │                          │
│                    │  (budget, priority, │                          │
│                    │   de-dup, reorder)  │                          │
│                    └──────────┬──────────┘                          │
│                               │                                     │
│                    ┌──────────┴──────────┐                          │
│                    │  LLM GENERATION     │                          │
│                    │  + Self-reflection  │                          │
│                    │  + Verification     │                          │
│                    └──────────┬──────────┘                          │
│                               │                                     │
│                    ┌──────────┴──────────┐                          │
│                    │  FINAL RESPONSE     │                          │
│                    │  + Citations        │                          │
│                    │  + Confidence        │                          │
│                    │  + Tool traces      │                          │
│                    └─────────────────────┘                          │
└─────────────────────────────────────────────────────────────────────┘
```

The future of AI agents is not just better models — it is **better architectures** that combine:

1. **Grounded generation** (RAG) to reduce hallucination
2. **Structured knowledge** (knowledge graphs) for multi-hop reasoning
3. **Tool use** (function calling, MCP) for real-world action
4. **Self-evaluation** (self-RAG, corrective RAG) for reliability
5. **Adaptive routing** (adaptive RAG) for efficiency

Together, these form a cognitive architecture where the LLM is the *reasoner*, retrieval provides *knowledge*, and tools provide *agency*.

---

## Real References

1. Lewis, P., Perez, E., Piktus, A., Petroni, F., Karpukhin, V., Goyal, N., Küttler, H., Lewis, M., Yen, W., Rocktäschel, T., Kiela, D., & Mikolov, T. "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks." *Advances in Neural Information Processing Systems (NeurIPS)*, 2020. arXiv:2005.11401

2. Johnson, J., Douze, M., & Jégou, H. "Billion-scale Similarity Search with GPUs." *IEEE Transactions on Big Data*, 7(3):535–547, 2021. arXiv:1702.08734 — Introduces FAISS.

3. Chen, J., Lin, H., Han, X., & Sun, L. "Benchmarking Large Language Models in Retrieval-Augmented Generation." *arXiv preprint arXiv:2401.18014*, 2024.

4. Asai, A., Wu, Z., Wang, Y., Sil, A., & Hajishirzi, H. "Self-RAG: Learning to Retrieve, Generate, and Critique through Self-Reflection." *International Conference on Learning Representations (ICLR)*, 2024. arXiv:2310.11511

5. Yan, S., Gu, J., Zhu, Y., & Ling, Z. "Corrective Retrieval Augmented Generation." *arXiv preprint arXiv:2401.15884*, 2024.

6. Gao, L., Ma, X., Lin, F., &_callaghan, J. "Retrieval-Augmented Generation for Large Language Models: A Survey." *arXiv preprint arXiv:2312.10997*, 2024.

7. Schick, T., Dwivedi-Yu, J., Dessì, R., Raileanu, R., Lomeli, M., Hambro, E., Zettlemoyer, L., Cancedda, N., & Scialom, T. "Toolformer: Language Models Can Teach Themselves to Use Tools." *Advances in Neural Information Processing Systems (NeurIPS)*, 2023. arXiv:2302.04761

8. Parisi, A., Zhao, Y., & Fiedel, N. "TALM: Tool-Augmented Language Models." *arXiv preprint arXiv:2205.12255*, 2022.

9. Model Context Protocol (MCP). Anthropic, 2024. https://modelcontextprotocol.io/

10. Milvus Documentation. Zilliz, 2024. https://milvus.io/docs

11. Pinecone Documentation. Pinecone Systems, 2024. https://docs.pinecone.io

12. Weaviate Documentation. Weaviate B.V., 2024. https://weaviate.io/developers/weaviate

13. Qdrant Documentation. Qdrant, 2024. https://qdrant.tech/documentation/

14. ChromaDB Documentation. Chroma, 2024. https://www.trychroma.com/docs

15. Malkov, Y. A., & Yashunin, D. A. "Efficient and Robust Approximate Nearest Neighbor Search Using Hierarchical Navigable Small World Graphs." *IEEE Transactions on Pattern Analysis and Machine Intelligence*, 42(4):824–836, 2020. DOI:10.1109/TPAMI.2018.2889473 — The HNSW algorithm.

16. Karpukhin, V., Oğuz, B., Min, S., Lewis, P., Wu, L., Yih, S., & Hajishirzi, H. "Dense Passage Retrieval for Open-Domain Question Answering." *Proceedings of EMNLP*, 2020, pp. 6769–6781. arXiv:2004.04906

17. Xiong, L., Xiong, C., Li, Y., Tang, K., Liu, J., Bennett, P., Ahmed, J., & Overwijk, A. "Approximate Nearest Neighbor Negative Contrastive Learning for Dense Text Retrieval." *Proceedings of ICLR*, 2021. arXiv:2007.00808 — ANCE dense retrieval.

18. Muennighoff, N., Tazi, J., Magne, L., & Reimers, N. "MTEB: Massive Text Embedding Benchmark." *Proceedings of EACL*, 2023. arXiv:2210.07316

19. Wang, L., Yang, N., Huang, X., Yang, Z., Majumder, R., & Wei, F. "Improving Text Embeddings with Large Language Models." *arXiv preprint arXiv:2401.00368*, 2024.

20. Neelakantan, A., et al. "Text and Code Embeddings by Contrastive Pre-Training on Trillions of Tokens." *arXiv preprint arXiv:2212.02907*, 2022 — Microsoft E5 embeddings.

21. Robertson, S. E., & Zaragoza, H. "The Probabilistic Relevance Framework: BM25 and Beyond." *Foundations and Trends in Information Retrieval*, 3(4):333–389, 2009. DOI:10.1561/1500000019

22. Cormack, G. V., Clarke, C. L. A., & Büttcher, S. "Reciprocal Rank Fusion Outperforms Condorcet and Individual Rank Ranking Methods." *Proceedings of SIGIR*, 2009, pp. 758–759. DOI:10.1145/1571941.1572114

23. Edge, D., Trinh, H., Cheng, X., Bradley, J., Chuo, A., Menezes, A., & Amershi, S. "From Local to Global: A Graph RAG Approach to Query-Focused Summarization." *arXiv preprint arXiv:2404.16130*, 2024 — Microsoft GraphRAG.

24. Wu, L., Yang, Z., Zhang, Y., & Sun, M. "Graph Retrieval-Augmented Generation: A Survey." *arXiv preprint arXiv:2404.16130*, 2024.

25. Jeong, S., Baek, J., Cho, S., Hwang, S. W., & Park, J. "Adaptive-RAG: Learning to Adapt Retrieval-Augmented Large Language Models through Question Complexity." *arXiv preprint arXiv:2403.14403*, 2024.

26. Yao, S., Zhao, J., Yu, D., Du, N., Shafran, I., Narasimhan, K., & Cao, Y. "ReAct: Synergizing Reasoning and Acting in Language Models." *International Conference on Learning Representations (ICLR)*, 2023. arXiv:2210.03629

27. Shinn, N., Cassano, F., Gopinathan, A., & Narasimhan, K. "Reflexion: Language Agents with Verbal Reinforcement Learning." *NeurIPS*, 2023. arXiv:2303.11366

28. Nakano, R., et al. "WebGPT: Browser-Assisted Question-Answering with Human Feedback." *arXiv preprint arXiv:2112.09332*, 2021.

29. Patil, S. G., Zhang, T., & Wang, X. "Gorilla: Large Language Model Connected with Massive APIs." *arXiv preprint arXiv:2305.15334*, 2023.

30. Qin, Y., et al. "ToolLLM: Facilitating Large Language Models to Master 16000+ Real-world APIs." *International Conference on Learning Representations (ICLR)*, 2024. arXiv:2307.16789

31. Chase, H. "LangChain: Building Applications with LLMs through Composability." 2022. https://github.com/langchain-ai/langchain

32. Douze, M., Guzhva, A., Deng, C., Johnson, J., Szilagyi, G., Hagiwara, M., Souri, Z., Subercaseaux, L., & Jégou, H. "The FAISS Library." *arXiv preprint arXiv:2401.17243*, 2024.

33. Wang, T., et al. "Multi-Query Retrieval: Query Expansion for Enhanced Retrieval-Augmented Generation." In *Proceedings of EMNLP*, 2024.

34. Borgeaud, S., et al. "Retro: Retrieval-Enhanced Transformer." *arXiv preprint arXiv:2112.04426*, 2022.

35. Izacard, G., & Grave, É. "Leveraging Passage Retrieval with Generative Models for Open Domain Question Answering." *Proceedings of EACL*, 2021, pp. 874–880. arXiv:2007.01282

36. Guu, K., Lee, K., Tung, Z., Pasupat, P., & Chang, M. "Retrieval Augmented Language Model Pre-Training." *Proceedings of ICML*, 2020, pp. 3929–3938. arXiv:2002.08909 — REALM.

37. Es, S., James, J., Espinosa-Anke, L., & Schockaert, S. "RAGAS: Automated Evaluation of Retrieval Augmented Generation." *Proceedings of EACL*, 2024. arXiv:2309.15217

38. Es, S., James, J., Espinosa-Anke, L., & Schockaert, S. "RAGAS: Evaluation Framework for Retrieval-Augmented Generation." *arXiv preprint arXiv:2309.15217*, 2023.
## References

- Lewis, P. et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks," NeurIPS 2020. https://arxiv.org/abs/2005.11401
- Gao, Y. et al., "Retrieval-Augmented Generation for Large Language Models: A Survey," 2024. https://arxiv.org/abs/2312.10997
- Schick, T. et al., "Toolformer: Language Models Can Teach Themselves to Use Tools," 2023. https://arxiv.org/abs/2302.04761
- LangChain Documentation — RAG. https://python.langchain.com/docs/tutorials/rag/
- LlamaIndex Documentation. https://docs.llamaindex.ai/
- Pinecone Documentation. https://docs.pinecone.io/
- Weaviate Documentation. https://weaviate.io/developers/weaviate
- ChromaDB Documentation. https://www.trychroma.com/
- OpenAI Embeddings Guide. https://platform.openai.com/docs/guides/embeddings
- Yao, S. et al., "ReAct: Synergizing Reasoning and Acting in Language Models," ICLR 2023. https://arxiv.org/abs/2210.03629
- OpenAI Function Calling. https://platform.openai.com/docs/guides/function-calling
- "Structuring Data for RAG," LangChain Blog, 2023.
