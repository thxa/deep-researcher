# Multi-Agent Orchestration and Workflows

## Table of Contents

1. [Orchestration Patterns](#1-orchestration-patterns)
2. [Routing and Dispatching Strategies](#2-routing-and-dispatching-strategies)
3. [Dynamic Agent Selection](#3-dynamic-agent-selection-based-on-task-type)
4. [State Machines for Agent Workflows](#4-state-machines-for-agent-workflows)
5. [LangGraph Deep Dive](#5-langgraph-deep-dive)
6. [Building Production-Grade Orchestrators](#6-building-production-grade-orchestrators)
7. [Handling Dependencies Between Agent Outputs](#7-handling-dependencies-between-agent-outputs)
8. [Streaming and Real-Time Orchestration](#8-streaming-and-real-time-orchestration)
9. [Error Handling, Timeouts, and Circuit Breakers](#9-error-handling-timeouts-and-circuit-breakers)
10. [Monitoring and Observability](#10-monitoring-and-observability)

---

## 1. Orchestration Patterns

Multi-agent orchestration defines how autonomous agents coordinate, communicate, and produce collective output. The choice of orchestration pattern determines latency, fault tolerance, cost, and output quality. Every pattern trades off between control and autonomy — more structured pipelines yield predictable results, while emergent patterns yield creative but unpredictable ones.

### 1.1 Sequential Pipelines (Linear Workflow)

The simplest and most predictable pattern. Each agent receives the output of its predecessor, processes it, and forwards the result downstream. Agents have no knowledge of upstream agents beyond the input they receive — they are functionally pure transformers.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SEQUENTIAL PIPELINE PATTERN                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐         │
│  │  Agent A │────►│  Agent B │────►│  Agent C │────►│  Agent D │          │
│  │ Research │     │ Analyze  │     │  Draft   │     │  Review  │          │
│  └──────────┘     └──────────┘     └──────────┘     └──────────┘         │
│       │                │                │                │                │
│       ▼                ▼                ▼                ▼                │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐         │
│  │  State:  │     │  State:  │     │  State:  │     │  State:  │          │
│  │ raw_data │     │ analyzed │     │ drafted  │     │ final    │          │
│  └──────────┘     └──────────┘     └──────────┘     └──────────┘         │
│                                                                             │
│  Data Flow:  User Input → A → B → C → D → Final Output                    │
│  Error Propagation:  If B fails, C and D never execute                     │
│  Latency:  T_total = T_A + T_B + T_C + T_D                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**When to use:** Content generation pipelines (research → outline → draft → edit), data transformation ETL workflows, any workflow where each step depends on the full output of the previous step.

**Trade-offs:**
- Latency is cumulative — total time is the sum of all agent execution times
- Single point of failure at every stage; one failed agent halts the entire pipeline
- Simplicity of reasoning; the state at each stage is deterministic given the input
- No parallelism; resources are underutilized if agents could operate concurrently

```python
from typing import TypedDict, Annotated
from operator import add

class PipelineState(TypedDict):
    raw_query: str
    research_results: str
    analysis: str
    draft: str
    final_output: str
    errors: Annotated[list[str], add]

def research_node(state: PipelineState) -> PipelineState:
    try:
        results = research_agent(state["raw_query"])
        return {"research_results": results}
    except Exception as e:
        return {"errors": [f"research: {e}"]}

def analyze_node(state: PipelineState) -> PipelineState:
    try:
        analysis = analysis_agent(state["research_results"])
        return {"analysis": analysis}
    except Exception as e:
        return {"errors": [f"analysis: {e}"]}

def draft_node(state: PipelineState) -> PipelineState:
    try:
        draft = drafting_agent(state["analysis"])
        return {"draft": draft}
    except Exception as e:
        return {"errors": [f"draft: {e}"]}

def review_node(state: PipelineState) -> PipelineState:
    try:
        final = review_agent(state["draft"])
        return {"final_output": final}
    except Exception as e:
        return {"errors": [f"review: {e}"]}

# Wire sequentially
graph = StateGraph(PipelineState)
graph.add_node("research", research_node)
graph.add_node("analyze", analyze_node)
graph.add_node("draft", draft_node)
graph.add_node("review", review_node)

graph.add_edge("research", "analyze")
graph.add_edge("analyze", "draft")
graph.add_edge("draft", "review")
```

### 1.2 Parallel Execution (Fan-Out / Fan-In)

Multiple agents execute concurrently on the same or partitioned input. A fan-out phase dispatches work to N agents; a fan-in phase aggregates their results. This is the foundational pattern for any workload that benefits from concurrent execution.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PARALLEL FAN-OUT / FAN-IN PATTERN                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                          ┌──────────┐                                      │
│                          │   FAN    │                                      │
│                          │  OUT     │                                      │
│                       ┌──┤ DISPATCH ├──┐                                   │
│                       │  └──────────┘  │                                   │
│                       │                │                                   │
│                ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐        │
│                │  Agent A    │   │  Agent B    │   │  Agent C    │        │
│                │ Web Search │   │ DB Query   │   │ Doc Search  │        │
│                └──────┬──────┘   └──────┬──────┘   └──────┬──────┘        │
│                       │                │                │                   │
│                       │  (concurrent)  │  (concurrent)  │                   │
│                       │                │                │                   │
│                ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐        │
│                │ Result A   │   │ Result B   │   │ Result C    │        │
│                └──────┬──────┘   └──────┬──────┘   └──────┬──────┘        │
│                       │                │                │                   │
│                       └────────┬───────┘───────────────┘                   │
│                          ┌──────▼──────┐                                   │
│                          │   FAN IN   │                                    │
│                          │ AGGREGATE  │                                    │
│                          └──────┬──────┘                                   │
│                          ┌──────▼──────┐                                   │
│                          │ Synthesized│                                    │
│                          │  Output    │                                    │
│                          └─────────────┘                                   │
│                                                                             │
│  Latency:  T_total = T_dispatch + max(T_A, T_B, T_C) + T_aggregate        │
│  Fault:    Partial failure possible — aggregate N/M results                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**When to use:** Multi-source research (query different data sources simultaneously), ensemble approaches where multiple perspectives improve quality, any embarrassingly parallel workload.

**Critical design decisions:**
- **Aggregation strategy**: Concatenation, voting, weighted merge, LLM-based synthesis
- **Partial failure**: If 1 of 3 agents fails, do you return partial results or retry?
- **Resource limits**: Parallel execution N may exceed rate limits; implement a concurrency semaphore

```python
import asyncio
from typing import Any

class FanOutFanIn:
    def __init__(self, agents: list, aggregator, max_concurrency: int = 5):
        self.agents = agents
        self.aggregator = aggregator
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def execute_agent(self, agent, input_data: Any) -> Any:
        async with self.semaphore:
            return await agent.run(input_data)

    async def run(self, input_data: Any) -> Any:
        tasks = [
            self.execute_agent(agent, input_data)
            for agent in self.agents
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful = [r for r in results if not isinstance(r, Exception)]
        failed = [r for r in results if isinstance(r, Exception)]

        if not successful:
            raise RuntimeError(f"All agents failed: {failed}")

        return self.aggregator(successful, errors=failed)
```

### 1.3 Map-Reduce Pattern

A special case of fan-out/fan-in where a large input is partitioned into chunks, each processed independently (map phase), and the results are merged (reduce phase). Differs from simple parallelism because the reduce step is itself a recursive or hierarchical operation.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MAP-REDUCE PATTERN                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ INPUT: "Analyze 1000 customer reviews and summarize themes"          │   │
│  └───────────────────┬─────────────────────────────────────────────────┘   │
│                      │                                                      │
│                      ▼                                                      │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │                    MAP PHASE (Partition)                          │     │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐       ┌─────────┐      │     │
│  │  │ Chunk 1 │  │ Chunk 2 │  │ Chunk 3 │  ...  │ Chunk N │       │     │
│  │  │reviews  │  │reviews  │  │reviews  │       │reviews  │      │     │
│  │  │ 1-100   │  │ 101-200 │  │ 201-300 │       │ 901-1000│      │     │
│  │  └────┬────┘  └────┬────┘  └────┬────┘       └────┬────┘      │     │
│  │       │            │            │                  │            │     │
│  │  ┌────▼────┐  ┌────▼────┐  ┌────▼────┐       ┌────▼────┐      │     │
│  │  │ Agent₁  │  │ Agent₂  │  │ Agent₃  │  ...  │ Agentₙ  │       │     │
│  │  │ analyze │  │ analyze │  │ analyze │       │ analyze │      │     │
│  │  └────┬────┘  └────┬────┘  └────┬────┘       └────┬────┘      │     │
│  │       │            │            │                  │            │     │
│  │  ┌────▼────┐  ┌────▼────┐  ┌────▼────┐       ┌────▼────┐      │     │
│  │  │Summary₁ │  │Summary₂ │  │Summary₃ │       │Summaryₙ │      │     │
│  │  └─────────┘  └─────────┘  └─────────┘       └─────────┘      │     │
│  └────────────────────────┬──────────────────────────────────────────┘     │
│                           │                                                 │
│                           ▼                                                 │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │                 REDUCE PHASE (Hierarchical Merge)                 │     │
│  │                                                                  │     │
│  │   Level 1:  ┌─────────┐  ┌─────────┐        ┌─────────┐        │     │
│  │   Merge:    │ Merge₁₂ │  │ Merge₃₄ │  ...   │ Mergeₙ₋₁ₙ│        │     │
│  │             └────┬────┘  └────┬────┘        └────┬────┘        │     │
│  │                  │            │                   │              │     │
│  │   Level 2:  ┌────▼────┐      ┌────▼────┐         │              │     │
│  │   Merge:    │Merge₁₋₄ │      │Merge₅₋₈ │  ...    │              │     │
│  │             └────┬────┘      └────┬────┘         │              │     │
│  │                  │               │                │              │     │
│  │   Final:    ┌────▼───────────────▼────────────────▼──┐           │     │
│  │   Merge:    │        GLOBAL SUMMARY / THEME LIST     │           │     │
│  │             └───────────────────────────────────────┘           │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  Latency:  O(log(N/chunk_size) * T_merge) + T_map                         │
│  Scale:    Handles arbitrarily large inputs via hierarchical reduction     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**When to use:** Processing large document collections, batch analysis of logs or reviews, any workload where input exceeds a single agent's context window, hierarchical summarization.

**Key considerations:**
- **Chunk boundary semantics**: Splitting mid-paragraph or mid-sentence loses context; use semantic chunk boundaries
- **Reduce operator choice**: Concatenation for simple aggregation, LLM-based synthesis for intelligent merging
- **Information loss at each level**: Each reduce step discards detail; calibrate depth-vs-fidelity trade-off
- **Idempotency**: Map tasks should be idempotent to support safe retries

```python
from typing import Any, Callable
import asyncio

class MapReduceOrchestrator:
    def __init__(
        self,
        map_agent: Any,
        reduce_agent: Any,
        chunker: Callable[[Any], list[Any]],
        max_concurrency: int = 10,
        reduce_batch_size: int = 5,
    ):
        self.map_agent = map_agent
        self.reduce_agent = reduce_agent
        self.chunker = chunker
        self.max_concurrency = max_concurrency
        self.reduce_batch_size = reduce_batch_size

    async def map_phase(self, chunks: list[Any]) -> list[Any]:
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def process_chunk(chunk):
            async with semaphore:
                return await self.map_agent.run(chunk)

        results = await asyncio.gather(
            *[process_chunk(c) for c in chunks],
            return_exceptions=True,
        )
        return [r for r in results if not isinstance(r, Exception)]

    async def reduce_phase(self, results: list[Any]) -> Any:
        if len(results) == 1:
            return results[0]

        batches = [
            results[i : i + self.reduce_batch_size]
            for i in range(0, len(results), self.reduce_batch_size)
        ]

        reduced = await asyncio.gather(
            *[self.reduce_agent.run(batch) for batch in batches]
        )
        return await self.reduce_phase(list(reduced))

    async def run(self, input_data: Any) -> Any:
        chunks = self.chunker(input_data)
        mapped = await self.map_phase(chunks)
        return await self.reduce_phase(mapped)
```

### 1.4 Pipeline with Branching

A directed acyclic graph (DAG) where agents may have multiple successors. After a node executes, a routing function determines which downstream agents should receive its output. This enables conditional logic, iterative refinement loops, and multi-path workflows within a single graph.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PIPELINE WITH BRANCHING (DAG)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                        ┌──────────┐                                        │
│                        │ ROUTER   │                                        │
│                        │ Agent    │                                        │
│                   ┌────┤  (classify)├────┐                                │
│                   │    └──────────┘     │                                 │
│                   │                     │                                  │
│            ┌──────▼──────┐       ┌──────▼──────┐                         │
│            │  RESEARCH   │       │  CREATIVE   │                         │
│            │  AGENT      │       │  AGENT      │                         │
│            └──────┬──────┘       └──────┬──────┘                         │
│                   │                     │                                  │
│            ┌──────▼──────┐       ┌──────▼──────┐                         │
│            │  FACT-CHECK │       │  EDITOR     │                         │
│            └──────┬──────┘       └──────┬──────┘                         │
│                   │                     │                                  │
│                   └────────┬────────────┘                                 │
│                          │                                                 │
│                    ┌─────▼──────┐                                          │
│                    │  MERGE     │                                          │
│                    │  AGENT     │                                          │
│                    └─────┬──────┘                                          │
│                          │                                                 │
│                    ┌─────▼──────┐                                          │
│                    │  QUALITY   │───── FAIL ────┐                        │
│                    │  GATE      │                  │                        │
│                    └─────┬──────┘           ┌─────▼──────┐                │
│                          │ PASS             │  REVISION  │                 │
│                          │                  │  LOOP      │──┐              │
│                    ┌─────▼──────┐           └────────────┘  │              │
│                    │  FINAL     │                  ┌─────────┘              │
│                    │  OUTPUT    │◄────────(retry)──┘                        │
│                    └────────────┘                                           │
│                                                                             │
│  Features:                                                                  │
│  • Conditional routing based on task classification                        │
│  • Parallel branches for different processing strategies                   │
│  • Quality gate with feedback loop (revision cycle)                        │
│  • DAG structure — no cycles except explicit revision loops                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**When to use:** Mixed task types (factual vs. creative), quality-gated outputs with revision cycles, workflows where subsequent steps depend on classification results.

**Implementation considerations:**
- **Cycle detection**: Ensure revision loops have a max iteration count to prevent infinite loops
- **State merging**: When branches converge, define a merge strategy (concatenation, LLM synthesis, structured merge)
- **Conditional edge evaluation**: Router decisions must be deterministic given the same input state

```python
from typing import TypedDict, Literal

class BranchingState(TypedDict):
    query: str
    task_type: str
    research_result: str
    creative_result: str
    merged_result: str
    quality_score: float
    revision_count: int
    final_output: str

def classify_query(state: BranchingState) -> str:
    classification = classifier_agent(state["query"])
    if classification in ("factual", "hybrid"):
        return "research"
    return "creative"

def quality_gate_router(state: BranchingState) -> str:
    if state["quality_score"] >= 0.8:
        return "finalize"
    if state["revision_count"] >= 3:
        return "finalize"
    return "revise"

graph = StateGraph(BranchingState)
graph.add_node("router", router_node)
graph.add_node("research", research_node)
graph.add_node("creative", creative_node)
graph.add_node("merge", merge_node)
graph.add_node("quality_gate", quality_gate_node)
graph.add_node("revise", revise_node)
graph.add_node("finalize", finalize_node)

graph.set_entry_point("router")
graph.add_conditional_edges("router", classify_query, {
    "research": "research",
    "creative": "creative",
})
graph.add_edge("research", "merge")
graph.add_edge("creative", "merge")
graph.add_edge("merge", "quality_gate")
graph.add_conditional_edges("quality_gate", quality_gate_router, {
    "finalize": "finalize",
    "revise": "revise",
})
graph.add_edge("revise", "merge")
```

---

## 2. Routing and Dispatching Strategies

Routing determines which agent handles a given task and how control flows between agents. In multi-agent systems, the router is itself often an LLM call — a lightweight classifier that inspects the input state and selects the next agent.

### Router Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DYNAMIC ROUTING FLOWCHART                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                         ┌─────────────┐                                    │
│                         │   INPUT     │                                    │
│                         │   TASK      │                                    │
│                         └──────┬──────┘                                    │
│                                │                                            │
│                         ┌──────▼──────┐                                    │
│                         │   INTENT    │                                    │
│                         │ CLASSIFIER  │                                    │
│                         │  (LLM/ML)  │                                    │
│                         └──────┬──────┘                                    │
│                                │                                            │
│              ┌─────────┬──────┼──────┬──────────┐                          │
│              │         │      │      │          │                           │
│         ┌────▼───┐┌────▼──┐┌─▼───┐┌─▼────┐┌────▼───┐                     │
│         │CODE    ││REASON ││CREATE││SEARCH││  MATH  │                     │
│         │AGENT   ││AGENT  ││AGENT ││AGENT ││  AGENT │                     │
│         └────┬───┘└────┬──┘└──┬──┘└──┬───┘└────┬───┘                     │
│              │         │      │      │         │                           │
│              └─────────┴──────┴──────┴─────────┘                           │
│                                │                                            │
│                         ┌──────▼──────┐                                    │
│                         │  VALIDATE   │                                    │
│                         │  &  ROUTE   │                                    │
│                         └──────┬──────┘                                    │
│                                │                                            │
│                     ┌──────────┼──────────┐                                │
│                     │          │          │                                │
│               ┌─────▼───┐ ┌───▼────┐ ┌───▼────┐                         │
│               │SINGLE   │ │MULTI   │ │ESCALATE│                          │
│               │AGENT    │ │AGENT   │ │TO HUMAN│                          │
│               │EXECUTE  │ │ORCHESTR│ │        │                          │
│               └─────────┘ └────────┘ └────────┘                          │
│                                                                             │
│  Routing Decision Factors:                                                 │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ 1. Task type classification (code, reasoning, creative, etc.)   │     │
│  │ 2. Complexity score → single agent vs. multi-agent pipeline       │     │
│  │ 3. Confidence threshold → escalate if below threshold           │     │
│  │ 4. Cost/latency budget → prefer cheaper agents when possible     │     │
│  │ 5. Agent availability → circuit-breaker status, current load    │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Router Implementation Strategies

**Strategy 1: LLM-based function-calling router.** Use a small, fast LLM with a structured output schema that emits a routing decision. This is the most flexible approach — it can handle ambiguous inputs and multi-label classification — but adds latency.

**Strategy 2: Embedding-based semantic router.** Embed the input, compare against precomputed agent-description embeddings using cosine similarity, and route to the nearest match. Extremely fast at inference time, but requires curated agent descriptions and embedding updates when agents change.

**Strategy 3: Rule-based router.** Keyword matching, regex, or heuristic rules. Zero inference latency, fully deterministic, but brittle and unable to handle novel inputs.

**Strategy 4: Hybrid router.** Use rules first (fast path for obvious cases), fall back to semantic routing for moderate confidence, and LLM-based routing for low confidence. This is the recommended approach for production systems.

```python
from enum import Enum
from dataclasses import dataclass

class AgentType(Enum):
    CODE = "code"
    REASONING = "reasoning"
    CREATIVE = "creative"
    SEARCH = "search"
    MATH = "math"
    ESCALATE = "escalate"

@dataclass
class RoutingDecision:
    agent_type: AgentType
    confidence: float
    requires_multi_agent: bool
    reasoning: str

class HybridRouter:
    def __init__(self, rules, semantic_router, llm_router, confidence_threshold=0.7):
        self.rules = rules
        self.semantic_router = semantic_router
        self.llm_router = llm_router
        self.confidence_threshold = confidence_threshold

    async def route(self, input_task: str) -> RoutingDecision:
        # Layer 1: Rule-based (instant, deterministic)
        rule_result = self.rules.match(input_task)
        if rule_result and rule_result.confidence > 0.95:
            return rule_result

        # Layer 2: Semantic embedding (fast, approximate)
        semantic_result = await self.semantic_router.route(input_task)
        if semantic_result.confidence > self.confidence_threshold:
            return semantic_result

        # Layer 3: LLM-based (slow, flexible)
        return await self.llm_router.route(input_task)
```

---

## 3. Dynamic Agent Selection Based on Task Type

Dynamic agent selection goes beyond routing — it involves constructing the agent pipeline at runtime based on the properties of the task. This is meta-orchestration: the orchestrator doesn't just choose *which* agent, but *how many*, *in what order*, and *with what configuration*.

### Selection Heuristics

| Task Property | Selection Strategy |
|---|---|
| Simple lookup | Single retrieval agent |
| Multi-step reasoning | Sequential pipeline (plan → execute → verify) |
| Large-scale processing | Map-reduce with parallel workers |
| Ambiguous intent | Fan-out to multiple interpreters, vote on best |
| High-stakes output | Parallel + consensus (multiple agents, agreement required) |
| Creative generation | Single creative agent with review loop |

### Dynamic Pipeline Assembly

```python
class DynamicOrchestrator:
    def __init__(self, agent_registry: dict, planner_agent):
        self.registry = agent_registry
        self.planner = planner_agent

    async def orchestrate(self, task: str, context: dict) -> dict:
        plan = await self.planner.plan(task, context)

        pipeline = []
        for step in plan.steps:
            agent = self.registry[step.agent_type]
            config = step.config_override or agent.default_config
            pipeline.append((agent, config, step.dependencies))

        results = {}
        for agent, config, deps in pipeline:
            resolved_input = self._resolve_deps(task, results, deps)
            results[agent.name] = await agent.run(resolved_input, config)

        return self._compile_output(results, plan)

    def _resolve_deps(self, original_task, results, deps):
        resolved = {"original_task": original_task}
        for dep in deps:
            if dep in results:
                resolved[dep] = results[dep]
        return resolved
```

---

## 4. State Machines for Agent Workflows

State machines provide formal correctness guarantees for agent workflows. Each state represents a well-defined execution context; transitions are triggered by events (agent completion, timeout, error). This model is superior to ad-hoc control flow because it makes all possible states and transitions explicit and testable.

### Finite State Machine Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              STATE MACHINE FOR AGENT WORKFLOW                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                          ┌─────────┐                                      │
│                          │  IDLE   │◄─────────────────────────┐           │
│                          └────┬────┘                           │           │
│                               │ new_task                       │           │
│                               ▼                                │           │
│                          ┌─────────┐                           │           │
│                    ┌────►│ PLANNING│──── task_too_complex ──┐   │           │
│                    │     └────┬────┘                        │   │           │
│                    │          │ plan_ready                   │   │           │
│                    │          ▼                              │   │           │
│                    │     ┌─────────┐    ┌──────────┐      │   │           │
│                    │     │DISPATCH │───►│ESCALATED │      │   │           │
│                    │     └────┬────┘    │  (Human)  │      │   │           │
│                    │          │         └────┬─────┘      │   │           │
│                    │          ▼              │             │   │           │
│                    │     ┌─────────┐   human_resolution   │   │           │
│                    │     │EXECUTING│──────────────────────►│   │           │
│                    │     └────┬────┘                       │   │           │
│                    │          │                            │   │           │
│                    │     ┌────┴────┐                       │   │           │
│                    │     │         │                       │   │           │
│                    │     ▼         ▼                       │   │           │
│                    │  ┌──────┐ ┌──────┐                    │   │           │
│                    │  │SUCCESS│ │FAILED │─── retry ────────┘   │           │
│                    │  └──┬───┘ └──┬───┘   max_retries ──►│          │           │
│                    │     │        │                       │   │           │
│                    │     ▼        │                       │   │           │
│                    │  ┌──────┐    │                       │   │           │
│                    │  │VERIFY│◄───┘                       │   │           │
│                    │  └──┬───┘                            │   │           │
│                    │     │                                 │   │           │
│                    │  ┌──┴──┐                              │   │           │
│                    │  │     │                              │   │           │
│                    │  ▼     ▼                              │   │           │
│                 ┌─────┐ ┌──────┐                          │   │           │
│                 │ACCEPT│ │REJECT├────── revise ────────────┘   │           │
│                 └──┬──┘ └──────┘                              │           │
│                    │                                          │           │
│                    ▼                                          │           │
│              ┌──────────┐                                     │           │
│              │COMPLETE  ├──────────────────────────────────────┘           │
│              └──────────┘                                                 │
│                                                                             │
│  States: IDLE, PLANNING, DISPATCH, EXECUTING, VERIFY, ACCEPT,              │
│          REJECT, COMPLETE, FAILED, ESCALATED                              │
│                                                                             │
│  Transitions (event-triggered):                                            │
│    IDLE → PLANNING        : new_task                                       │
│    PLANNING → DISPATCH    : plan_ready                                     │
│    PLANNING → ESCALATED   : task_too_complex                               │
│    DISPATCH → EXECUTING   : agents_started                                 │
│    EXECUTING → SUCCESS    : all_agents_completed                           │
│    EXECUTING → FAILED     : agent_error / timeout                          │
│    FAILED → EXECUTING     : retry (if attempts < max)                      │
│    SUCCESS → VERIFY       : output_ready                                   │
│    VERIFY → ACCEPT        : quality_threshold_met                          │
│    VERIFY → REJECT        : quality_threshold_not_met                       │
│    REJECT → DISPATCH      : revise (loop back)                             │
│    ESCALATED → DISPATCH   : human_resolution                               │
│    ACCEPT → COMPLETE      : done                                           │
│    COMPLETE → IDLE        : reset                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Statecharts (Hierarchical State Machines)

Statecharts extend FSMs with nested states, orthogonal regions, and history. This is essential for multi-agent systems where each agent is itself a state machine, and the orchestrator must track higher-level workflow state *and* individual agent states simultaneously.

- **Nested states**: EXECUTING contains sub-states PER_AGENT (each agent has IDLE → RUNNING → DONE)
- **Orthogonal regions**: Research and Creative branches can execute in parallel within EXECUTING
- **History state**: After a crash, the orchestrator can resume from the last known state rather than starting over

```python
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Callable

class WorkflowState(Enum):
    IDLE = auto()
    PLANNING = auto()
    DISPATCHING = auto()
    EXECUTING = auto()
    VERIFYING = auto()
    COMPLETED = auto()
    FAILED = auto()
    ESCALATED = auto()

class WorkflowEvent(Enum):
    NEW_TASK = auto()
    PLAN_READY = auto()
    TASK_TOO_COMPLEX = auto()
    AGENTS_STARTED = auto()
    ALL_AGENTS_DONE = auto()
    AGENT_ERROR = auto()
    QUALITY_PASS = auto()
    QUALITY_FAIL = auto()
    RETRY = auto()
    HUMAN_RESOLUTION = auto()
    RESET = auto()

@dataclass
class StateMachine:
    transitions: dict[tuple[WorkflowState, WorkflowEvent], WorkflowState] = field(default_factory=dict)
    current: WorkflowState = WorkflowState.IDLE
    retry_count: int = 0
    max_retries: int = 3

    def on_event(self, event: WorkflowEvent) -> WorkflowState:
        key = (self.current, event)
        if key not in self.transitions:
            raise InvalidTransition(f"No transition from {self.current} on {event}")
        self.current = self.transitions[key]

        if self.current == WorkflowState.EXECUTING and event == WorkflowEvent.RETRY:
            self.retry_count += 1

        return self.current

    def can_retry(self) -> bool:
        return self.retry_count < self.max_retries

# Define the state machine from the diagram above
sm = StateMachine(transitions={
    (WorkflowState.IDLE, WorkflowEvent.NEW_TASK): WorkflowState.PLANNING,
    (WorkflowState.PLANNING, WorkflowEvent.PLAN_READY): WorkflowState.DISPATCHING,
    (WorkflowState.PLANNING, WorkflowEvent.TASK_TOO_COMPLEX): WorkflowState.ESCALATED,
    (WorkflowState.DISPATCHING, WorkflowEvent.AGENTS_STARTED): WorkflowState.EXECUTING,
    (WorkflowState.EXECUTING, WorkflowEvent.ALL_AGENTS_DONE): WorkflowState.VERIFYING,
    (WorkflowState.EXECUTING, WorkflowEvent.AGENT_ERROR): WorkflowState.FAILED,
    (WorkflowState.FAILED, WorkflowEvent.RETRY): WorkflowState.EXECUTING,
    (WorkflowState.VERIFYING, WorkflowEvent.QUALITY_PASS): WorkflowState.COMPLETED,
    (WorkflowState.VERIFYING, WorkflowEvent.QUALITY_FAIL): WorkflowState.DISPATCHING,
    (WorkflowState.ESCALATED, WorkflowEvent.HUMAN_RESOLUTION): WorkflowState.DISPATCHING,
    (WorkflowState.COMPLETED, WorkflowEvent.RESET): WorkflowState.IDLE,
})
```

---

## 5. LangGraph Deep Dive

LangGraph is the de facto framework for building stateful, multi-actor AI workflows. It models agent orchestration as a directed graph where nodes are compute units (agents, functions, tools) and edges define control flow. The key insight: **the graph's state is a shared, typed data structure that every node reads from and writes to**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LANGGRAPH ARCHITECTURE                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    STATE (TypedDict / Pydantic)                    │   │
│  │  ┌──────────────────────────────────────────────────────────┐     │   │
│  │  │ {                                                         │     │   │
│  │  │   messages: [HumanMessage, AIMessage, ...],              │     │   │
│  │  │   documents: [Document, ...],                            │     │   │
│  │  │   current_step: "research",                              │     │   │
│  │  │   iterations: 2,                                         │     │   │
│  │  │   metadata: {...}                                        │     │   │
│  │  │ }                                                         │     │   │
│  │  └──────────────────────────────────────────────────────────┘     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  NODES (functions that read/write State)                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ planner  │  │ researcher│  │  coder   │  │ reviewer │  │ finalizer│   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │              │              │              │              │          │
│       ▼              ▼              ▼              ▼              ▼          │
│  EDGES (control flow between Nodes)                                        │
│  ┌────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │   Normal Edge:     planner ──────► researcher                       │   │
│  │                                                                        │   │
│  │   Conditional:     researcher ──► [code_needed?] ──► coder            │   │
│  │                                        └────────► reviewer           │   │
│  │                                                                        │   │
│  │   Loop:            reviewer ──► [quality_ok?] ──► finalizer           │   │
│  │                              └──── [needs_work] ──► researcher       │   │
│  │                                                                        │   │
│  └────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  SUBGRAPHS                                                                 │
│  ┌─────────────────────────────────────────────────┐                     │
│  │  Main Graph                                      │                     │
│  │  ┌──────────┐    ┌────────────────────────┐     │                     │
│  │  │  entry   │───►│  research_subgraph      │     │                     │
│  │  └──────────┘    │  ┌──────┐  ┌────────┐   │     │                     │
│  │                  │  │search│──►│analyze │   │     │                     │
│  │                  │  └──────┘  └────────┘   │     │                     │
│  │                  └────────────┬─────────────┘     │                     │
│  │                               │                   │                     │
│  │                  ┌────────────▼─────────────┐     │                     │
│  │                  │  coding_subgraph         │     │                     │
│  │                  │  ┌──────┐  ┌────────┐    │     │                     │
│  │                  │  │write│──►│  test  │    │     │                     │
│  │                  │  └──────┘  └────────┘    │     │                     │
│  │                  └──────────────────────────-┘     │                     │
│  └─────────────────────────────────────────────────┘                     │
│                                                                             │
│  PERSISTENCE: Checkpointers (SqliteSaver, PostgresSaver) store state      │
│  at every node, enabling: pause/resume, time-travel debugging, human-in-   │
│  the-loop approval gates.                                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### State

State is the central shared data structure. Every node reads from it and writes updates to it. LangGraph uses reducer semantics: when a node returns a partial state update, the framework merges it with the existing state using annotated reducer functions.

```python
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

class ResearchState(TypedDict):
    messages: Annotated[list, add_messages]
    query: str
    research_notes: list[str]
    draft: str
    review_feedback: list[str]
    iteration: int
    max_iterations: int
```

Key state design principles:
- **Use Annotated reducers** for accumulative fields (messages, lists) rather than overwriting
- **Keep state minimal** — only store what downstream nodes actually need; avoid bloating state with intermediate artifacts
- **Make state serializable** — required for checkpointing; avoid storing file handles, connections, or lambda functions
- **Version your state schema** — when deploying changes, ensure backward compatibility with existing checkpoints

### Nodes

A node is a plain Python function that receives the current `State` and returns a partial state update. Nodes should be pure functions with minimal side effects. Side effects (API calls, database writes) should be explicit and handled within the node body.

```python
def research_node(state: ResearchState) -> dict:
    query = state["query"]
    notes = research_agent.invoke(query)
    return {
        "research_notes": state.get("research_notes", []) + [notes],
        "messages": [HumanMessage(content=f"Research complete for: {query}")],
    }

def draft_node(state: ResearchState) -> dict:
    context = "\n".join(state["research_notes"])
    draft = drafting_agent.invoke(f"Draft based on:\n{context}")
    return {"draft": draft}

def review_node(state: ResearchState) -> dict:
    feedback = review_agent.invoke(state["draft"])
    return {
        "review_feedback": state.get("review_feedback", []) + [feedback],
        "iteration": state.get("iteration", 0) + 1,
    }
```

### Edges

Edges define control flow. **Normal edges** are unconditional: after node A, always go to node B. **Conditional edges** route based on state: after node A, call a function that inspects the current state and returns the name of the next node.

```python
def should_continue(state: ResearchState) -> str:
    if state["iteration"] >= state["max_iterations"]:
        return "finalize"
    last_feedback = state["review_feedback"][-1] if state["review_feedback"] else ""
    if "APPROVED" in last_feedback:
        return "finalize"
    return "draft"

graph.add_conditional_edges("review", should_continue, {
    "draft": "draft",
    "finalize": "finalize",
})
```

### Subgraphs

Subgraphs encapsulate reusable multi-node workflows. A subgraph has its own state schema, which can differ from the parent graph's state. LangGraph handles state mapping between parent and child via input/output transforms.

```python
class ResearchSubgraphState(TypedDict):
    query: str
    search_results: list[str]
    analysis: str

research_subgraph = StateGraph(ResearchSubgraphState)
research_subgraph.add_node("search", search_node)
research_subgraph.add_node("analyze", analyze_node)
research_subgraph.add_edge("search", "analyze")
research_subgraph.set_entry_point("search")

# Add as node in parent graph
parent_graph.add_node("research", research_subgraph.compile())
```

### Checkpointing and Persistence

LangGraph supports checkpointing via backends like `SqliteSaver` and `PostgresSaver`. At every node execution boundary, the full state is serialized to the checkpoint store. This enables:

1. **Pause/resume**: Interrupt a long-running workflow and resume later
2. **Time-travel debugging**: Replay a workflow from any prior checkpoint
3. **Human-in-the-loop**: Insert approval gates where execution suspends until a human approves

```python
from langgraph.checkpoint.sqlite import SqliteSaver

with SqliteSaver.from_conn_string(":memory:") as checkpointer:
    graph = app.compile(
        checkpointer=checkpointer,
        interrupt_before=["finalize"],
    )
    config = {"configurable": {"thread_id": "thread-1"}}
    result = graph.invoke(initial_state, config)
    # Workflow pauses before 'finalize' node
    # Human reviews state, then:
    result = graph.invoke(None, config)  # Resumes from checkpoint
```

---

## 6. Building Production-Grade Orchestrators

Production orchestrators must handle concerns far beyond the happy path. Below is a comprehensive architecture for a production-grade system.

### Architecture Components

1. **Task Queue**: Decouples task submission from execution. Redis streams, SQS, or Kafka. Enables backpressure, retries, and prioritization.
2. **Orchestration Engine**: The state machine / graph executor. LangGraph compiled graph, Temporal workflow, or custom FSM.
3. **Agent Pool**: A managed set of agent workers. Each agent is a stateless compute unit that receives a task, executes it, and returns a result.
4. **State Store**: Durable state persistence. Postgres, Redis, or a dedicated workflow state store.
5. **Event Bus**: Pub/sub for inter-agent communication, progress updates, and monitoring. Redis Pub/Sub, Kafka, or cloud event bridges.
6. **Observability Stack**: Metrics, logs, traces. OpenTelemetry → Prometheus → Grafana.

```python
class ProductionOrchestrator:
    def __init__(
        self,
        graph: CompiledGraph,
        task_queue: TaskQueue,
        state_store: StateStore,
        event_bus: EventBus,
        agent_pool: AgentPool,
        config: OrchestratorConfig,
    ):
        self.graph = graph
        self.task_queue = task_queue
        self.state_store = state_store
        self.event_bus = event_bus
        self.agent_pool = agent_pool
        self.config = config

    async def submit_task(self, task: Task) -> str:
        task_id = str(uuid4())
        await self.state_store.initialize(task_id, task)
        await self.task_queue.enqueue(task_id, task, priority=task.priority)
        await self.event_bus.publish("task.submitted", {"task_id": task_id})
        return task_id

    async def process_task(self, task_id: str):
        state = await self.state_store.load(task_id)
        try:
            config = {"configurable": {"thread_id": task_id}}
            result = await self.graph.ainvoke(state, config)
            await self.state_store.save(task_id, result)
            await self.event_bus.publish("task.completed", {"task_id": task_id})
        except Exception as e:
            await self.state_store.mark_failed(task_id, str(e))
            await self.event_bus.publish("task.failed", {"task_id": task_id, "error": str(e)})
```

### Production Checklist

- **Idempotency**: Every node must be idempotent. Use idempotency keys on external API calls.
- **Rate limiting**: Implement per-agent, per-provider rate limiters. Use token bucket algorithms.
- **Timeout budgets**: Assign a timeout budget per node and per total workflow. Fail fast on budget exceeded.
- **Retry with exponential backoff**: Retry transient failures with jittered exponential backoff.
- **Dead letter queues**: Failed tasks after max retries go to a DLQ for human inspection.
- **Graceful degradation**: If a non-critical agent fails, return partial results rather than failing the entire workflow.
- **Version pinning**: Pin agent model versions. A model update can change output format and break downstream nodes.

---

## 7. Handling Dependencies Between Agent Outputs

Agent dependencies form a DAG. When Agent C needs outputs from both A and B, the orchestrator must ensure A and B complete before C starts, and must resolve potential conflicts between A's and B's outputs.

```
Dependency Types:

  Sequential:    A ──► B ──► C         C needs B, B needs A
  
  Parallel:     A ──┐
                       ├──► C          C needs both A and B
                 B ──┘

  Conditional:  A ──► [filter] ──► C   C only needs A if condition met

  Iterative:    A ──► B ──► A         A revises based on B's output
```

### Resolving Conflicts

When parallel agents produce conflicting outputs, the orchestrator needs a conflict resolution strategy:

1. **Last-writer-wins**: Simplest; last agent to write wins. Works when one agent is canonical.
2. **Merge function**: Custom logic that combines partial results (e.g., union of document sets).
3. **LLM-based arbitration**: An arbitration agent ingests both outputs and produces a merged version.
4. **Priority-based**: Each agent has a priority score; higher priority wins conflicts.
5. **Consensus voting**: Multiple agents vote; majority wins. Requires ≥3 agents.

```python
class DependencyResolver:
    def __init__(self, conflict_strategy: str = "arbitrate"):
        self.conflict_strategy = conflict_strategy

    async def resolve(
        self,
        outputs: dict[str, Any],
        dependencies: dict[str, list[str]],
    ) -> dict[str, Any]:
        resolved = {}
        execution_order = self._topological_sort(dependencies)
        pending = set(outputs.keys())

        for node in execution_order:
            deps = dependencies.get(node, [])
            dep_outputs = {d: resolved[d] for d in deps if d in resolved}

            if len(dep_outputs) > 1:
                resolved[node] = await self._resolve_conflict(outputs[node], dep_outputs)
            else:
                resolved[node] = outputs[node]

        return resolved

    async def _resolve_conflict(self, current_output, conflicting_outputs):
        if self.conflict_strategy == "arbitrate":
            return await arbitration_agent.invoke({
                "conflicting": conflicting_outputs,
                "current": current_output,
            })
        elif self.conflict_strategy == "priority":
            return max(conflicting_outputs.values(), key=lambda x: x.priority)
        return current_output

    def _topological_sort(self, dependencies: dict) -> list[str]:
        visited, order = set(), []
        def visit(node):
            if node not in visited:
                visited.add(node)
                for dep in dependencies.get(node, []):
                    visit(dep)
                order.append(node)
        for node in dependencies:
            visit(node)
        return order
```

---

## 8. Streaming and Real-Time Orchestration

In production, users expect progressive results — not a blank screen while agents work for minutes. Streaming in multi-agent systems has two orthogonal dimensions:

1. **Token streaming**: Individual tokens streamed from LLM responses (horizontal within a node)
2. **Node streaming**: Intermediate results streamed as nodes complete (vertical across the graph)

### Token-Level Streaming

Each agent streams its output token-by-token. The orchestrator must multiplex these streams to the client, annotating each token with its source agent.

```python
async def stream_agent_output(agent, input_data, source: str):
    async for token in agent.astream(input_data):
        yield {"type": "token", "source": source, "content": token}
```

### Node-Level Streaming (LangGraph `astream_events`)

LangGraph provides `astream_events` which emits events for every node start, node completion, and token produced. This gives the client a complete picture of workflow progress.

```python
async def stream_workflow(graph, initial_state, config):
    async for event in graph.astream_events(initial_state, config, version="v2"):
        if event["event"] == "on_chain_start":
            yield {
                "type": "node_start",
                "node": event["name"],
                "timestamp": event["timestamp"],
            }
        elif event["event"] == "on_chain_end":
            yield {
                "type": "node_complete",
                "node": event["name"],
                "output": event["data"]["output"],
                "timestamp": event["timestamp"],
            }
        elif event["event"] == "on_chat_model_stream":
            yield {
                "type": "token",
                "node": event["name"],
                "content": event["data"]["chunk"].content,
            }
```

### Server-Sent Events (SSE) to Client

```python
from fastapi import FastAPI
from fastapi.responses import StreamingResponse

app = FastAPI()

@app.post("/research/stream")
async def stream_research(query: str):
    async def event_generator():
        async for event in stream_workflow(graph, {"query": query}, config):
            yield f"data: {json.dumps(event)}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")
```

### Backpressure and Buffering

When downstream consumers are slower than upstream agents, the orchestrator must handle backpressure. Strategies:
- **Buffer with limit**: Queue up to N events, then apply backpressure to producers
- **Sample/throttle**: Drop intermediate tokens, keep only node-level events
- **Priority streams**: Always stream node completion events; token streaming is best-effort

---

## 9. Error Handling, Timeouts, and Circuit Breakers

Multi-agent systems fail in complex ways. A single LLM API timeout, a malformed output, or a downstream service outage can cascade through the entire workflow. Production systems need layered defenses.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              ERROR HANDLING FLOW WITH CIRCUIT BREAKERS                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │                     AGENT EXECUTION ATTEMPT                       │     │
│  └─────────────────────────┬─────────────────────────────────────────┘     │
│                            │                                                │
│                            ▼                                                │
│                  ┌───────────────────┐                                     │
│                  │  CIRCUIT BREAKER   │                                     │
│                  │  ┌───────────────┐ │                                     │
│                  │  │   STATE:      │ │                                     │
│                  │  │   CLOSED      │ │  ← Normal: requests flow through   │
│                  │  │   OPEN        │ │  ← Tripped: requests rejected     │
│                  │  │   HALF-OPEN   │ │  ← Probing: test if recovered     │
│                  │  └───────────────┘ │                                     │
│                  └─────────┬─────────┘                                     │
│                            │                                                │
│              ┌─────────────┼─────────────┐                                 │
│              │             │             │                                   │
│         STATE=CLOSED  STATE=OPEN    STATE=HALF-OPEN                        │
│              │             │             │                                   │
│              ▼             │             │                                   │
│   ┌──────────────┐        │             │                                   │
│   │  EXECUTE     │        │             │                                   │
│   │  AGENT CALL  │        │             │                                   │
│   └──────┬───────┘        │             │                                   │
│          │                │             │                                   │
│     ┌────┴────┐           │             │                                   │
│     │         │            │             │                                   │
│  SUCCESS    FAILURE        │             │                                   │
│     │         │            │             │                                   │
│     │    ┌────▼───────┐   │             │                                   │
│     │    │ INCREMENT   │   │             │                                   │
│     │    │ FAILURE     │   │             │                                   │
│     │    │ COUNTER     │   │             │                                   │
│     │    └────┬────────┘  │             │                                   │
│     │         │            │             │                                   │
│     │    ┌────▼────────┐  │             │                                   │
│     │    │ COUNTER >=   │  │             │                                   │
│     │    │ THRESHOLD?   │  │             │                                   │
│     │    └──┬────────┬─┘  │             │                                   │
│     │    YES│       NO│   │             │                                   │
│     │       │        │   │             │                                   │
│     │  ┌────▼────┐   │   │             │                                   │
│     │  │  TRIP   │   │   │             │                                   │
│     │  │  OPEN   │   │   │             │                                   │
│     │  │  STATE  │   │   │             │                                   │
│     │  └─────────┘   │   │             │                                   │
│     │                │   │             │                                   │
│     │  ┌─────────┐   │   │             │                                   │
│     │  │ RETRY   │   │   │             │                                   │
│     │  │ W/ BACK │◄──┘   │             │                                   │
│     │  │  OFF    │       │             │                                   │
│     │  └────┬────┘       │             │                                   │
│     │       │            │             │                                   │
│     │  ┌────▼────┐       │             │                                   │
│     │  │ RESULT  │       │             │                                   │
│     │  │ RETURN  │       │             │                                   │
│     │  └─────────┘       │             │                                   │
│     │                     │             │                                   │
│     │              ┌──────▼───────┐     │                                   │
│     │              │  FALLBACK    │     │                                   │
│     │              │  RESPONSE    │     │                                   │
│     │              │  OR FAIL     │     │                                   │
│     │              └──────────────┘     │                                   │
│     │                                    │                                   │
│     │                            ┌──────▼───────┐                         │
│     │                            │  PROBE CALL   │                        │
│     │                            │  (TEST CALL)  │                        │
│     │                            └──────┬───────┘                         │
│     │                                   │                                    │
│     │                              ┌────┴────┐                             │
│     │                           SUCCESS    FAIL                             │
│     │                              │         │                             │
│     │                     ┌───────▼───┐ ┌───▼──────┐                      │
│     │                     │ CLOSE     │ │ STAY OPEN │                      │
│     │                     │ CIRCUIT   │ │ RESET    │                      │
│     │                     │ TIMER     │ │ TIMER    │                      │
│     │                     └───────────┘ └──────────┘                      │
│                                                                             │
│  TIMEOUT LAYERS:                                                            │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ Level 1: Node timeout (per-agent)           e.g., 60s           │     │
│  │ Level 2: Step timeout (per-orchestration-step) e.g., 120s       │     │
│  │ Level 3: Workflow timeout (total budget)     e.g., 300s          │     │
│  │ Level 4: Request timeout (client-facing)     e.g., 600s          │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Circuit Breaker Implementation

```python
import asyncio
import time
from enum import Enum
from dataclasses import dataclass, field

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

@dataclass
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 3
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    half_open_calls: int = 0

    @property
    def is_available(self) -> bool:
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.half_open_calls = 0
                return True
            return False
        if self.state == CircuitState.HALF_OPEN:
            return self.half_open_calls < self.half_open_max_calls
        return False

    def record_success(self):
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            self.half_open_calls += 1
            if self.success_count >= self.half_open_max_calls:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
        self.failure_count = 0

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
        elif self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN

class ResilientAgentRunner:
    def __init__(self, agents: dict[str, Any], timeout: float = 60.0):
        self.circuits = {name: CircuitBreaker() for name in agents}
        self.agents = agents
        self.timeout = timeout

    async def run(self, agent_name: str, input_data: Any) -> Any:
        circuit = self.circuits[agent_name]

        if not circuit.is_available:
            raise CircuitOpenError(f"Circuit breaker open for {agent_name}")

        try:
            result = await asyncio.wait_for(
                self.agents[agent_name].arun(input_data),
                timeout=self.timeout,
            )
            circuit.record_success()
            return result
        except asyncio.TimeoutError:
            circuit.record_failure()
            raise AgentTimeoutError(f"Agent {agent_name} timed out after {self.timeout}s")
        except Exception as e:
            circuit.record_failure()
            raise AgentExecutionError(f"Agent {agent_name} failed: {e}") from e
```

### Timeout Budgets

Each workflow node, step, and total execution must have timeout budgets. The orchestrator should fail fast when budgets are exceeded, rather than allowing indefinite hangs.

```python
@dataclass
class TimeoutBudget:
    node_timeout: float = 60.0
    step_timeout: float = 120.0
    workflow_timeout: float = 300.0
    client_timeout: float = 600.0

async def execute_with_budget(agent, input_data, budget: TimeoutBudget, elapsed: float):
    remaining = budget.workflow_timeout - elapsed
    node_budget = min(budget.node_timeout, remaining)
    if node_budget <= 0:
        raise WorkflowTimeoutError("Workflow timeout budget exhausted")
    return await asyncio.wait_for(agent.arun(input_data), timeout=node_budget)
```

---

## 10. Monitoring and Observability for Multi-Agent Workflows

Observability in multi-agent systems requires three pillars — **metrics**, **logs**, and **traces** — with agent-specific dimensions added to every signal.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│          MONITORING ARCHITECTURE FOR MULTI-AGENT SYSTEMS                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │                    INSTRUMENTED AGENTS                             │     │
│  │                                                                   │     │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐       ┌─────────┐       │     │
│  │  │ Agent A │  │ Agent B │  │ Agent C │  ...  │ Agent N │        │     │
│  │  │ ┌─────┐ │  │ ┌─────┐ │  │ ┌─────┐ │       │ ┌─────┐ │       │     │
│  │  │ │ OTEL│ │  │ │ OTEL│ │  │ │ OTEL│ │       │ │ OTEL│ │       │     │
│  │  │ │ instr│ │  │ │ instr│ │  │ │ instr│ │       │ │ instr│ │       │     │
│  │  │ └──┬──┘ │  │ └──┬──┘ │  │ └──┬──┘ │       │ └──┬──┘ │       │     │
│  │  └────┼────┘  └────┼────┘  └────┼────┘       └────┼────┘       │     │
│  └───────┼────────────┼────────────┼─────────────────┼────────────┘     │
│          │             │             │                  │                    │
│          └─────────────┼─────────────┼──────────────────┘                   │
│                        │             │                                      │
│                        ▼             ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │                   OPEN TELEMETRY COLLECTOR                        │     │
│  │                                                                   │     │
│  │   Receivers:  OTLP(gRPC), OTLP(HTTP), Prometheus                  │     │
│  │   Processors: batch, attributes, tail-sampling                    │     │
│  │   Exporters:  OTLP → Tempo, Prometheus, Loki                      │     │
│  │                                                                   │     │
│  └───────────┬─────────────────┬──────────────────┬──────────────────┘    │
│              │                 │                   │                         │
│              ▼                 ▼                   ▼                         │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐              │
│  │     TEMPO       │ │   PROMETHEUS    │ │      LOKI       │              │
│  │  (Traces)       │ │  (Metrics)      │ │  (Logs)         │              │
│  │                 │ │                 │ │                 │              │
│  │  • span traces │ │  • latency p99  │ │  • agent logs   │              │
│  │  • DAG viz     │ │  • error rates  │ │  • error traces │              │
│  │  • causality   │ │  • token usage  │ │  • audit trail  │              │
│  │  • throughput  │ │  • cost/tracking │ │  • state diffs  │              │
│  └────────┬────────┘ └────────┬────────┘ └────────┬────────┘              │
│           │                    │                    │                        │
│           └────────────────────┼────────────────────┘                        │
│                                │                                             │
│                                ▼                                             │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │                      GRAFANA DASHBOARDS                          │     │
│  │                                                                   │     │
│  │  ┌──────────────────────┐  ┌──────────────────────┐             │     │
│  │  │  WORKFLOW OVERVIEW   │  │  AGENT PERFORMANCE   │             │     │
│  │  │                      │  │                      │             │     │
│  │  │  • Active workflows │  │  • Per-agent latency  │             │     │
│  │  │  • Success/fail rate│  │  • Error rate by type│             │     │
│  │  │  • Avg completion   │  │  • Token consumption  │             │     │
│  │  │  • Queue depth      │  │  • Circuit breaker    │             │     │
│  │  └──────────────────────┘  └──────────────────────┘             │     │
│  │                                                                   │     │
│  │  ┌──────────────────────┐  ┌──────────────────────┐             │     │
│  │  │  COST TRACKING       │  │  TRACE EXPLORER       │             │     │
│  │  │                      │  │                      │             │     │
│  │  │  • $/workflow        │  │  • End-to-end trace  │             │     │
│  │  │  • $/agent           │  │  • Span waterfall    │             │     │
│  │  │  • Token utilization │  │  • DAG visualization │             │     │
│  │  │  • Budget compliance│  │  • Debug timeline    │             │     │
│  │  └──────────────────────┘  └──────────────────────┘             │     │
│  └───────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  KEY METRICS:                                                              │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │ workflow_duration_seconds (histogram) — labels: workflow_type    │     │
│  │ workflow_success_total (counter) — labels: workflow_type         │     │
│  │ workflow_failure_total (counter) — labels: workflow_type, error  │     │
│  │ agent_duration_seconds (histogram) — labels: agent_name          │     │
│  │ agent_token_usage_total (counter) — labels: agent_name, model    │     │
│  │ agent_error_total (counter) — labels: agent_name, error_type     │     │
│  │ circuit_breaker_state (gauge) — labels: agent_name                │     │
│  │ active_workflows (gauge) — labels: workflow_type                 │     │
│  │ queue_depth (gauge) — labels: priority                            │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### OpenTelemetry Instrumentation

Every agent invocation should produce a span with structured attributes. This enables distributed tracing across the entire workflow.

```python
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.metrics import MeterProvider

tracer = trace.get_tracer("orchestrator")
meter = metrics.get_meter("orchestrator")

workflow_duration = meter.create_histogram(
    "workflow_duration_seconds",
    description="End-to-end workflow duration",
    unit="s",
)

agent_duration = meter.create_histogram(
    "agent_duration_seconds",
    description="Per-agent execution duration",
    unit="s",
)

agent_tokens = meter.create_counter(
    "agent_token_usage_total",
    description="Total tokens consumed per agent",
)

agent_errors = meter.create_counter(
    "agent_error_total",
    description="Total errors per agent",
)

async def traced_agent_run(agent_name: str, agent, input_data: dict):
    with tracer.start_as_current_span(f"agent.{agent_name}") as span:
        span.set_attribute("agent.name", agent_name)
        span.set_attribute("agent.model", getattr(agent, "model_name", "unknown"))

        try:
            start = time.time()
            result = await agent.arun(input_data)
            duration = time.time() - start

            agent_duration.record(duration, {"agent_name": agent_name})
            agent_tokens.add(result.get("token_usage", 0), {"agent_name": agent_name})

            span.set_attribute("agent.status", "success")
            return result
        except Exception as e:
            agent_errors.add(1, {"agent_name": agent_name, "error_type": type(e).__name__})
            span.set_attribute("agent.status", "error")
            span.set_attribute("agent.error", str(e))
            span.set_status(trace.StatusCode.ERROR, str(e))
            raise
```

### Structured Logging

```python
import structlog

logger = structlog.get_logger()

async def logged_agent_run(agent_name: str, agent, input_data: dict):
    log = logger.bind(agent=agent_name, workflow_id=input_data.get("workflow_id"))

    log.info("agent_started", input_preview=input_data["query"][:100])

    try:
        result = await agent.arun(input_data)
        log.info(
            "agent_completed",
            duration_ms=result.get("duration_ms"),
            tokens=result.get("token_usage"),
            output_preview=str(result["output"])[:100],
        )
        return result
    except Exception as e:
        log.error("agent_failed", error=str(e), error_type=type(e).__name__)
        raise
```

### Alerting Rules

```yaml
# Prometheus alerting rules for multi-agent systems
groups:
  - name: multi_agent_alerts
    rules:
      - alert: AgentHighErrorRate
        expr: rate(agent_error_total[5m]) / rate(agent_duration_seconds_count[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Agent {{ $labels.agent_name }} error rate > 10%"

      - alert: CircuitBreakerOpen
        expr: circuit_breaker_state{state="open"} == 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Circuit breaker open for {{ $labels.agent_name }}"

      - alert: WorkflowTimeoutBudget
        expr: histogram_quantile(0.95, workflow_duration_seconds) > 250
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "P95 workflow duration exceeding timeout budget"

      - alert: HighTokenUsage
        expr: rate(agent_token_usage_total[1h]) > 1000000
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Agent {{ $labels.agent_name }} consuming > 1M tokens/hour"

      - alert: QueueDepthCritical
        expr: queue_depth > 1000
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Task queue depth > 1000, system may be overloaded"
```

---

## Summary

Multi-agent orchestration is the backbone of production AI systems. The choice of pattern — sequential, parallel, map-reduce, or branching DAG — determines your system's latency, fault tolerance, and scalability characteristics. Routing strategies blend speed and flexibility, with hybrid routers recommended for production. State machines provide correctness guarantees, while LangGraph provides the graph execution framework with built-in checkpointing. Production systems require circuit breakers, timeout budgets, structured observability, and graceful degradation at every layer. Build with these patterns, instrument everything, and test failure modes exhaustively.

---

## Real References

1. LangChain AI. "LangGraph: Build Stateless and Stateful Multi-Actor Applications." LangGraph Documentation, 2024. URL: https://langchain-ai.github.io/langgraph/

2. CrewAI. "CrewAI: Framework for Orchestrating Role-Playing Autonomous AI Agents." CrewAI Documentation, 2024. URL: https://docs.crewai.com/

3. Microsoft Research. "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation." AutoGen Documentation, 2024. URL: https://microsoft.github.io/autogen/

4. Wu, Q., Bansal, G., Zhang, J., Wu, Y., Li, B., Zhu, E., Jiang, L., Zhang, X., Zhang, S., Liu, J., Awadallah, A. H., White, R. W., Burger, D., Wang, C., "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation." arXiv preprint arXiv:2308.08155, 2023.

5. Hong, S., Zhuge, M., Chen, J., Zheng, X., Cheng, Y., Wang, J., "MetaGPT: Meta Programming for A Multi-Agent Collaborative Framework." In Proceedings of the International Conference on Learning Representations (ICLR 2024), arXiv:2308.00352.

6. Hohpe, G., Woolf, B., *Enterprise Integration Patterns: Designing, Building, and Deploying Messaging Solutions.* Addison-Wesley, 2003. ISBN: 978-0321200686.

7. Gamma, E., Helm, R., Johnson, R., Vlissides, J., *Design Patterns: Elements of Reusable Object-Oriented Software.* Addison-Wesley, 1994. ISBN: 978-0201633610.

8. Nygard, M. T., *Release It!: Design and Deploy Production-Ready Software*, 2nd Edition. Pragmatic Bookshelf, 2018. ISBN: 978-1680502398.

9. Harel, D., "Statecharts: A Visual Formalism for Complex Systems." *Science of Computer Programming*, vol. 8, no. 3, pp. 231–274, 1987. DOI: 10.1016/0167-6423(87)90035-9.

10. Dean, J., Ghemawat, S., "MapReduce: Simplified Data Processing on Large Clusters." In *Proceedings of the 6th USENIX Symposium on Operating Systems Design and Implementation (OSDI '04)*, pp. 137–150, 2004.

11. Netflix Technology Blog. "Circuit Breaker Pattern." In *Netflix TechBlog*, 2012. See also: Netflix Hystrix. URL: https://netflixtechblog.com/

12. Richardson, C., *Microservices Patterns: With Examples in Java.* Manning Publications, 2018. ISBN: 978-1617294549. (Covers circuit breaker, retry, and timeout patterns applicable to distributed agent systems.)

13. van der Aalst, W. M. P., ter Hofstede, A. H. M., Kiepuszewski, B., Barros, A. P., "Workflow Patterns." *Distributed and Parallel Databases*, vol. 14, no. 1, pp. 5–51, 2003. DOI: 10.1023/A:1022883727209.

14. Russell, N., ter Hofstede, A. H. M., van der Aalst, W. M. P., Mulyar, N., "Workflow Control-Flow Patterns: A Revised View." BPM Center Report BPM-06-22, 2006. URL: https://www.workflowpatterns.com/

15. Temporal Technologies. "Temporal: Durable Execution Platform for Production Workflows." Temporal Documentation, 2024. URL: https://temporal.io/

16. OpenTelemetry Authors. "OpenTelemetry: A Unified Observability Framework." OpenTelemetry Documentation, 2024. URL: https://opentelemetry.io/

17. Park, J. S., O'Brien, J. C., Cai, C. J., Morris, M. R., Liang, P., Bernstein, M. S., "Generative Agents: Interactive Simulacra of Human Behavior." In *Proceedings of the 36th ACM Symposium on User Interface Software and Technology (UIST 2023)*, arXiv:2304.03442.

18. Qian, C., Liu, W., Liu, H., Chen, N., Dang, Y., Li, J., Yang, C., Chen, W., Su, Y., Cong, X., Xu, J., Li, D., Liu, Z., Sun, M., "ChatDev: Communicative Agents for Software Development." In *Proceedings of the 62nd Annual Meeting of the Association for Computational Linguistics (ACL 2024)*, arXiv:2307.07924.

19. Dibia, V., Chen, J., Bansal, G., Syed, S., Fourney, A., Zhu, E., Wang, C., Amershi, S., "AutoGen Studio: A No-Code Platform for Building Multi-Agent Workflows." Microsoft Research, 2024. arXiv:2408.15247.

20. Wang, L., Ma, C., Feng, X., Zhang, Z., Yang, H., Zhang, J., Chen, Z., Tang, J., Chen, X., Lin, Y., Zhao, W. X., Wei, Z., Liu, W., "A Survey on Large Language Model Based Autonomous Agents." *Frontiers of Computer Science*, vol. 18, no. 6, 2024. arXiv:2308.11432.

21. Talebirad, Y., Nadiri, A., "Multi-Agent Collaboration: Harnessing the Power of Cooperative LLM Agents for Complex Task Solving." arXiv preprint arXiv:2306.03314, 2023.

22. Wu, Q., Zhang, J., Wu, Y., Bansal, G., Zhu, E., Gonzalez, J., Awadallah, A. H., "AutoGen + LangGraph: Building Stateful Multi-Agent Workflows." Microsoft Research Blog, 2024.

23. Shinn, N., Cassano, F., Berman, E., Gopinath, A., Narasimhan, K., Yao, S., "Reflexion: Language Agents with Verbal Reinforcement Learning." In *Advances in Neural Information Processing Systems (NeurIPS 2023)*, arXiv:2303.11366.

24. Signficant Gravitas. "AutoGPT: An Autonomous GPT-4 Agent." GitHub Repository, 2023. URL: https://github.com/Significant-Gravitas/AutoGPT

25. Cormen, T. H., Leiserson, C. E., Rivest, R. L., Stein, C., *Introduction to Algorithms*, 4th Edition. MIT Press, 2022. ISBN: 978-0262046305. (Covers DAGs, topological sort, and algorithmic foundations relevant to orchestration dependency resolution.)

26. Dijkstra, E. W., "Solution of a Problem in Concurrent Programming Control." *Communications of the ACM*, vol. 8, no. 9, p. 569, 1965. DOI: 10.1145/365559.365617. (Foundational work on mutual exclusion and concurrency control.)

27. Harel, D., Politi, M., *Modeling Reactive Systems with Statecharts: The Statemate Approach.* McGraw-Hill, 1998. ISBN: 978-0070262058.

28. Kleppmann, M., *Designing Data-Intensive Applications.* O'Reilly Media, 2017. ISBN: 978-1449373320. (Covers distributed systems patterns including fan-out/fan-in, map-reduce, and fault tolerance.)

29. Nygard, M. T., "Release It! Circuit Breaker, Bulkhead, and Timeout Patterns." *Pragmatic Programmer Series*, 2018.

30. Google Cloud. "Google Cloud Pub/Sub and Fan-Out/Fan-In Patterns." Google Cloud Architecture Center, 2024. URL: https://cloud.google.com/architecture
## References

- LangGraph Documentation — LangChain. https://langchain-ai.github.io/langgraph/
- Wu, Q. et al., "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation," 2023. https://arxiv.org/abs/2308.08155
- CrewAI Documentation. https://docs.crewai.com/
- Yao, S. et al., "ReAct: Synergizing Reasoning and Acting in Language Models," ICLR 2023. https://arxiv.org/abs/2210.03629
- "LangChain: Building Applications with LLMs through Composability." https://docs.langchain.com/
- OpenAI Function Calling Guide. https://platform.openai.com/docs/guides/function-calling
- PetMints, "Orchestration Patterns for LLM-Based Agents," 2023.
- Kim, G. et al., "Language Models as Solvers and Engines for Multi-Agent Systems," 2023.
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
- Anthropic Documentation. https://docs.anthropic.com
