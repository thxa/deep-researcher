# Agentic AI Fundamentals and Core Concepts

> A deep technical reference for understanding, designing, and reasoning about agentic AI systems.

---

## Table of Contents

1. [What is Agentic AI?](#1-what-is-agentic-ai)
2. [Core Agent Components](#2-core-agent-components)
3. [The ReAct Pattern](#3-the-react-pattern)
4. [Tool Use and Function Calling](#4-tool-use-and-function-calling)
5. [Planning Algorithms](#5-planning-algorithms)
6. [Memory Systems](#6-memory-systems)
7. [Agent Loops and Control Flow](#7-agent-loops-and-control-flow)
8. [Prompt Engineering for Agents](#8-prompt-engineering-for-agents)
9. [Safety and Guardrails](#9-safety-and-guardrails)
10. [Reflection and Self-Correction](#10-reflection-and-self-correction)
11. [The Autonomy Spectrum](#11-the-autonomy-spectrum)

---

## 1. What is Agentic AI?

### Definition

**Agentic AI** refers to artificial intelligence systems that exhibit **goal-directed autonomous behavior**—systems that can perceive their environment, reason about what to do, take actions, and adapt their strategy over time without requiring step-by-step human instruction for every decision.

Unlike traditional AI, which maps a single input to a single output (a function), agentic AI maps a **goal** to a **trajectory of interleaved reasoning and action** steps that unfold over time.

### Agentic AI vs. Traditional AI

| Dimension | Traditional AI | Agentic AI |
|---|---|---|
| Execution model | Single-pass inference | Multi-step loops with branching |
| Input | Static prompt | Evolving context + observations |
| Output | One-shot completion | Sequence of actions + final answer |
| Tool access | None or hardcoded | Dynamically selected and composed |
| Memory | Stateless (per call) | Persistent across steps and sessions |
| Error handling | Fail and retry externally | Self-correct within the loop |
| Planning | Implicit (in prompt) | Explicit decomposition and scheduling |
| Adaptation | None | Reflect, replan, adjust strategy |

### The Core Insight

A traditional language model answers: *"Given this input, what is the output?"*

An agentic system answers: *"Given this goal, what sequence of observations, thoughts, and actions will achieve it?"*

This shift from **prediction** to **pursuit** is what makes agentic AI fundamentally different. The agent is not just generating text—it is **navigating a problem space**, using tools as extensions of its capability, memory as its experience, and planning as its compass.

---

## 2. Core Agent Components

An agentic AI system is composed of five interlocking subsystems that work together in a continuous loop.

### Agent Anatomy Diagram

```
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                         AGENTIC AI SYSTEM                                │
 │                                                                         │
 │  ┌───────────┐    ┌──────────────────────────────────────────────┐      │
 │  │           │    │              REASONING ENGINE                │      │
 │ │  PERCEPTION│───▶│                                              │      │
 │ │           │    │  ┌─────────┐  ┌───────────┐  ┌────────────┐ │      │
 │ │ ┌───────┐ │    │  │ Planner │  │  Inferer  │  │  Reflector │ │      │
 │ │ │Observ-│ │    │  │         │  │           │  │            │ │      │
 │ │ │ations │ │    │  │ Goal    │  │ Evidence  │  │ Critique   │ │      │
 │ │ │Events │ │    │  │ decomp- │  │ analysis  │  │ Self-     │ │      │
 │ │ │Inputs │ │    │  │ osition │  │ deduct-   │  │ correction│ │      │
 │ │ │Sensor │ │    │  │         │  │ ion       │  │            │ │      │
 │ │ │data   │ │    │  └────┬────┘  └─────┬─────┘  └─────┬──────┘ │      │
 │ │ └───────┘ │    │       │              │              │        │      │
 │ │           │    │       ▼              ▼              ▼        │      │
 │ │ ┌───────┐ │    │  ┌─────────────────────────────────────────┐ │      │
 │ │ │Context│ │    │  │         WORKING MEMORY                   │ │      │
 │ │ │parser│ │    │  │   (scratchpad, chain of thought)         │ │      │
 │ │ └───────┘ │    │  └──────────────────┬──────────────────────┘ │      │
 │  │           │    │                     │                       │      │
 │  └─────┬─────┘    │                     ▼                       │      │
 │        │          │  ┌─────────────────────────────────────────┐ │      │
 │        │          │  │       DECISION SELECTOR                 │ │      │
 │        │          │  │  (choose next action from candidates)   │ │      │
 │        │          │  └──────────────────┬──────────────────────┘ │      │
 │        │          └─────────────────────┼────────────────────────┘      │
 │        │                                │                                │
 │        │          ┌─────────────────────▼────────────────────┐          │
 │        │          │              ACTION EXECUTOR              │          │
 │        │          │  ┌──────┐ ┌──────┐ ┌──────┐ ┌────────┐  │          │
 │        │          │  │Tool A│ │Tool B│ │Tool C│ │Tool N..│  │          │
 │        │          │  │Search│ │Code  │ │API   │ │Custom  │  │          │
 │        │          │  └──────┘ └──────┘ └──────┘ └────────┘  │          │
 │        │          └─────────────────────┬────────────────────┘          │
 │        │                                │                                │
 │        ▼                                ▼                                │
 │  ┌───────────────────────────────────────────────────────────────┐      │
 │ │                    ENVIRONMENT / WORLD                        │      │
 │ │   (APIs, filesystems, browsers, databases, sandboxes, users)  │      │
 │ └───────────────────────────────────────────────────────────────┘      │
 │                                                                         │
 │  ┌──────────────┐                          ┌──────────────────────┐     │
 │ │   LONG-TERM   │◀──── persistence ────────│   EPISODIC MEMORY    │     │
 │ │   MEMORY       │    (vector store,        │   (past trajectory   │     │
 │ │  (knowledge    │     knowledge graph)      │    logs, outcomes)    │     │
 │ │   base, DB)   │                          └──────────────────────┘     │
 │ └──────────────┘                                                       │
 └─────────────────────────────────────────────────────────────────────────┘
```

### Component Descriptions

**Perception** ingests raw signals from the environment—API responses, user messages, sensor data, file contents—and transforms them into structured observations that the reasoning engine can consume. A perception module may include parsers, filter pipelines, and format normalizers.

**Reasoning** is the cognitive core. It encompasses planning (decomposing goals), inference (drawing conclusions from evidence), and reflection (critiquing its own reasoning). The reasoning engine operates on the contents of **working memory**—the scratchpad where the agent's chain of thought is maintained step by step.

**Action** is the agent's means of affecting the world. Each action is selected from a repertoire of tools, and each tool has a defined interface (schema, preconditions, postconditions). The action executor handles serialization, invocation, rate limiting, and error capture.

**Memory** has two primary dimensions: **temporal** (short-term vs. long-term) and **representational** (episodic vs. semantic). Working memory holds the current reasoning trace; long-term memory persists knowledge across sessions. Episodic memory records *what happened*; semantic memory records *what was learned*.

**Planning** bridges goal and action. It decomposes high-level objectives into actionable sub-goals, orders them by dependency, and revises the plan when reality diverges from expectation.

---

## 3. The ReAct Pattern

**ReAct** (Yao et al., 2022) unifies **Reasoning** and **Acting** into a single interleaved loop. Rather than reasoning in isolation and then acting, or acting without explicit reasoning, ReAct alternates between the two at each step.

### ReAct Loop Flowchart

```
                          ┌──────────────┐
                          │   USER GOAL  │
                          └──────┬───────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   OBSERVE environment  │◀───────────────────┐
                    │   (read prior context  │                    │
                    │    + new observations) │                    │
                    └────────────┬───────────┘                    │
                                 │                                │
                                 ▼                                │
              ┌──────────────────────────────────────┐            │
              │          THINK (Reason)               │            │
              │                                      │            │
              │  • Analyze current state              │            │
              │  • Identify what information is needed│            │
              │  • Decide next step                   │            │
              │  • Consider alternatives             │            │
              │                                      │            │
              └──────────────────┬───────────────────┘            │
                                 │                                │
                    ┌────────────┴─────────────┐                   │
                    │                          │                   │
                    ▼                          ▼                   │
            ┌──────────────┐          ┌───────────────┐            │
            │  Need more   │          │  Have enough  │            │
            │  information │          │  information  │            │
            │  or action?  │          │  to answer?   │            │
            └──────┬───────┘          └───────┬───────┘            │
                   │                          │                    │
                   ▼                          ▼                    │
          ┌───────────────┐          ┌────────────────┐           │
          │ ACT (Execute) │          │  OUTPUT RESULT  │           │
          │               │          │                 │           │
          │ • Call tool   │          │  Return final    │           │
          │ • Query API   │          │  answer to user │           │
          │ • Read file   │          └────────┬────────┘           │
          │ • Run code    │                   │                    │
          └───────┬───────┘                   │                    │
                  │                           │                    │
                  ▼                           │                    │
          ┌───────────────┐                   │                    │
          │  OBSERVE      │                   │                    │
          │  (capture     │                   │                    │
          │   tool output)│───────────────────┼────────────────────┘
          └───────────────┘                   │                    │
                                              │                    │
                                              ▼                    │
                                        ┌────────────┐             │
                                        │  COMPLETE  │             │
                                        │  (done)    │─────────────┘
                                        └────────────┘
```

### Example Trace

```
Question: What is the population of the capital of the country that contains the city of Lyon?

Thought 1: I need to find what country Lyon is in. Let me search for that.
Action 1: Search("Lyon city country")
Observation 1: Lyon is a city in France.

Thought 2: Now I know Lyon is in France. I need the capital of France.
Action 2: Search("capital of France")
Observation 2: The capital of France is Paris.

Thought 3: Now I need the population of Paris.
Action 3: Search("population of Paris")
Observation 3: Paris has a population of approximately 2.16 million (city), 12.4 million (metro).

Thought 4: I have the answer. The population of Paris, the capital of France (the country containing Lyon), is approximately 2.16 million.
Action 4: Finish("Approximately 2.16 million")
```

### Why ReAct Matters

- **Grounding**: Actions produce real observations that ground reasoning in external truth rather than hallucinated knowledge.
- **Transparency**: Each thought is explicit, making the agent's decision process auditable.
- **Recovery**: If a thought leads to a wrong action, the observation exposes the error and the agent can self-correct in the next iteration.
- **Compositionality**: Complex goals decompose naturally into sequences of think-act-observe triples.

---

## 4. Tool Use and Function Calling

### What Are Tools?

Tools are **structured interfaces** between the agent and the external world. A tool is defined by:

1. **Name**: Unique identifier (e.g., `web_search`, `execute_python`)
2. **Description**: Natural-language explanation of what the tool does and when to use it
3. **Input schema**: JSON Schema defining expected parameters with types and constraints
4. **Output schema**: The shape of the result the tool returns
5. **Preconditions**: What must be true before the tool can be called
6. **Side effects**: Whether the tool is read-only or modifies state

### Function Calling Protocol

```
┌────────────────────────────────────────────────────────────────┐
 │                    FUNCTION CALLING FLOW                       │
 │                                                               │
 │  ┌──────────┐     ┌──────────┐     ┌──────────┐              │
 │  │   LLM    │     │  Tool    │     │  Tool    │              │
 │  │  Reasoner│     │ Router   │     │ Executor │              │
 │  └────┬─────┘     └────┬─────┘     └────┬─────┘              │
 │       │                 │                 │                    │
 │  1. Generate         2. Validate       3. Execute            │
 │     tool_call          schema             tool                │
 │     {                   {               Async/               │
 │       name: "search",    name,             sync               │
 │       args: {            args →            invocation          │
 │         query: "..."   validate            │                   │
 │       }               against            4. Capture           │
 │     }                 schema               result              │
 │       │                 │                 {                     │
 │       ▼                 │                   status: "success", │
 │  ┌──────────────────────┤                   data: {...}        │
 │  │  Serialization &    │                 }                     │
 │  │  validation         │                  │                    │
 │  └──────────┬───────────┘                 │                    │
 │             │                              │                    │
 │             ▼                              ▼                    │
 │        ┌───────────────────────────────────────┐              │
 │        │  OBSERVATION injection into context    │              │
 │        │  (formatted result appended to          │              │
 │        │   conversation / scratchpad)            │              │
 │        └───────────────────────────────────────┘               │
 └────────────────────────────────────────────────────────────────┘
```

### Tool Schema Example

```json
{
  "name": "execute_python",
  "description": "Execute Python code in a sandboxed environment. Use for calculations, data analysis, and code generation tasks.",
  "parameters": {
    "type": "object",
    "properties": {
      "code": {
        "type": "string",
        "description": "The Python code to execute"
      },
      "timeout": {
        "type": "integer",
        "description": "Execution timeout in seconds (default: 30, max: 120)",
        "default": 30
      }
    },
    "required": ["code"]
  },
  "returns": {
    "type": "object",
    "properties": {
      "stdout": { "type": "string" },
      "stderr": { "type": "string" },
      "exit_code": { "type": "integer" }
    }
  }
}
```

### Tool Selection Strategies

- **Single-tool selection**: The LLM picks one tool per step. Simple but limits parallelism.
- **Parallel tool calling**: The LLM proposes multiple independent tool calls in one step, executed concurrently.
- **Compositional tool use**: Output of one tool becomes input to the next, forming a pipeline.
- **Conditional tool use**: The agent decides whether calling a tool is worthwhile by estimating expected information gain vs. cost.

### Key Design Principles

1. **Tool descriptions are prompts** — the quality of the description directly determines when and how the agent invokes a tool.
2. **Minimize ambiguity** — overlapping tool capabilities cause selection errors; each tool should have a clearly distinct purpose.
3. **Fail gracefully** — tools should return structured errors, not crash. The agent must be able to interpret failure and adapt.
4. **Respect boundaries** — sandboxed execution, rate limiting, and permission scoping prevent tools from causing unintended side effects.

---

## 5. Planning Algorithms

Planning is the process of decomposing a goal into a structured sequence or tree of sub-goals and actions. Different algorithms offer different trade-offs between compute cost, solution quality, and robustness.

### 5.1 Chain of Thought (CoT)

CoT prompts the model to reason step-by-step before producing a final answer. No external search or backtracking.

```
 ┌─────────────────────────────────────┐
 │       CHAIN OF THOUGHT (CoT)        │
 │                                     │
 │   Input ──▶ Step 1 ──▶ Step 2 ──▶ ... ──▶ Step N ──▶ Answer  │
 │                                     │
 │   • Linear, sequential              │
 │   • No branching or backtracking   │
 │   • O(N) compute for N steps       │
 │   • Quality depends on each step   │
 │     being correct (error cascades) │
 └─────────────────────────────────────┘
```

### 5.2 Tree of Thoughts (ToT)

ToT explores **multiple reasoning paths** at each step, evaluates them, and searches (BFS/DFS) through the tree to find the best solution.

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │                TREE OF THOUGHTS (ToT)                                │
 │                                                                      │
 │                         ┌────────┐                                   │
 │                         │ Input  │                                   │
 │                         └───┬────┘                                   │
 │                             │                                        │
 │              ┌──────────────┼──────────────┐                        │
 │              ▼              ▼              ▼                        │
 │         ┌────────┐    ┌────────┐    ┌────────┐                     │
 │         │Thought1│    │Thought2│    │Thought3│   ◀── Generate       │
 │         └───┬────┘    └───┬────┘    └───┬────┘       multiple      │
 │             │             │             │           candidate       │
 │          [evaluate]    [evaluate]    [evaluate]     thoughts      │
 │          score:0.9    score:0.3    score:0.7                       │
 │             │             │             │                           │
 │             ▼             ✗             ▼                           │
 │      ┌──────────┐   (prune)      ┌──────────┐   ◀── Keep top-k    │
 │      │ Expand   │                 │ Expand   │      candidates     │
 │      │ further  │                 │ further  │                     │
 │      └──────────┘                 └──────────┘                     │
 │                                                                      │
 │   • Branching search with evaluation at each depth                  │
 │   • BFS or DFS with pruning                                        │
 │   • O(b^d) compute for branching factor b, depth d                 │
 │   • Robust against dead ends—can backtrack and try alternatives     │
 └──────────────────────────────────────────────────────────────────────┘
```

### 5.3 Graph of Thoughts (GoT)

GoT generalizes ToT by allowing **merging** of thought paths, **refining** of existing thoughts, and **cyclic** dependencies—forming a directed acyclic graph (DAG) or even cycles.

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │                GRAPH OF THOUGHTS (GoT)                                │
 │                                                                      │
 │                        ┌────────┐                                    │
 │                        │ Input  │                                    │
 │                        └───┬────┘                                    │
 │                            │                                         │
 │               ┌────────────┼────────────┐                            │
 │               ▼            ▼            ▼                            │
 │          ┌────────┐  ┌────────┐  ┌────────┐                         │
 │          │ThoughtA │  │ThoughtB │  │ThoughtC │                        │
 │          └───┬────┘  └────┬───┘  └────┬───┘                          │
 │              │            │           │                               │
 │              │      ┌─────┴──────┐    │                              │
 │              │      │  MERGE     │    │   ◀── Combine insights         │
 │              │      │  A+B→D    │    │       from multiple paths      │
 │              │      └─────┬──────┘    │                              │
 │              │            │           │                               │
 │              │            ▼           │                               │
 │              │       ┌────────┐      │                               │
 │              │       │ThoughtD│◀─────┘   ◀── Refine using            │
 │              │       │(merged)│             combined knowledge        │
 │              │       └───┬────┘                                       │
 │              │           │                                             │
 │              │     ┌─────┴──────┐                                     │
 │              │     │  REFINE    │    ◀── Iterate on merged thought    │
 │              │     │  D→D'      │                                       │
 │              │     └─────┬──────┘                                     │
 │              │           │                                             │
 │              └─────▶ ┌───▼───┐                                        │
 │                      │Answer │                                        │
 │                      └───────┘                                        │
 │                                                                      │
 │   • DAG structure with merge and refine operations                  │
 │   • Thoughts can be combined, revised, and recycled                 │
 │   • More expressive than ToT at higher compute cost                │
 │   • Suitable for tasks requiring synthesis of diverse perspectives  │
 └──────────────────────────────────────────────────────────────────────┘
```

### 5.4 Plan-and-Solve

Plan-and-Solve separates planning into two distinct phases: first generate a complete plan, then execute it step by step, with optional re-planning on failure.

```
 ┌─────────────────────────────────────────────────────────────┐
 │              PLAN-AND-SOLVE                                  │
 │                                                             │
 │  Phase 1: PLAN                                              │
 │  ┌────────────────────────────────────────────────────┐     │
 │  │  Goal: "Analyze the impact of climate policy on     │     │
 │  │         renewable energy adoption in Europe"        │     │
 │  │                                                     │     │
 │  │  Plan:                                              │     │
 │  │   1. Search for EU climate policy documents         │     │
 │  │   2. Search for renewable energy statistics Europe   │     │
 │  │   3. Analyze correlation between policy and adoption │     │
 │  │   4. Identify key case studies                      │     │
 │  │   5. Synthesize findings into a report               │     │
 │  └──────────────────────┬─────────────────────────────┘     │
 │                         │                                   │
 │  Phase 2: EXECUTE       │                                   │
 │  ┌──────────────────────▼─────────────────────────────┐     │
 │  │  Step 1 ──▶ Step 2 ──▶ Step 3 ──▶ Step 4 ──▶ Step5│     │
 │  │    │                                                │     │
 │  │    └── (if failure or deviation detected) ──┐      │     │
 │  │                                              │      │     │
 │  │  Phase 3: RE-PLAN (conditional)              │      │     │
 │  │  ┌───────────────────────────────────────────▼───┐  │     │
 │  │  │  Reassess remaining steps based on new info    │  │     │
 │  │  │  Modify plan ──▶ Continue execution             │  │     │
 │  │  └────────────────────────────────────────────────┘  │     │
 │  └─────────────────────────────────────────────────────┘     │
 └─────────────────────────────────────────────────────────────┘
```

### Planning Algorithm Comparison

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    ALGORITHM COMPARISON                                │
 │                                                                        │
 │  Metric          │  CoT       │  ToT         │  GoT        │ P&S      │
 │──────────────────┼────────────┼──────────────┼─────────────┼──────────│
 │  Structure       │  Linear    │  Tree        │  Graph/DAG  │  Seq+plan│
 │  Backtracking    │  None      │  Yes (prune) │  Yes (merge) │  Re-plan │
 │  Compute cost    │  O(N)      │  O(b^d)      │  O(V+E)     │  O(N+R) │
 │  Error recovery  │  None      │  Good        │  Best       │  Good    │
 │  Parallelism     │  None      │  Moderate    │  High       │  Stepwise│
 │  Best for        │  Simple    │  Search      │  Synthesis  │  Multi   │
 │                  │  reasoning │  problems    │  tasks      │  step    │
 │──────────────────┼────────────┼──────────────┼─────────────┼──────────│
 │  Quality vs Cost │  Low cost  │  Med cost    │  High cost  │  Medium │
 │                  │  Low qual  │  High qual   │  Best qual  │  Good   │
 └────────────────────────────────────────────────────────────────────────┘

  Quality ──────────────────────────────────────────▶
  │
  │  CoT ──▶ ToT ──▶ GoT
  │   ▲                 ▲
  │   │                 │
  │   └── P&S (variable, depends on re-plan count)
  │
  Cost  ──────────────────────────────────────────▶
```

---

## 6. Memory Systems

Memory is what enables an agent to learn from experience, maintain context over long interactions, and avoid repeating the same mistakes.

### Memory Architecture for Agents

```
 ┌──────────────────────────────────────────────────────────────────────────┐
 │                       AGENT MEMORY ARCHITECTURE                          │
 │                                                                          │
 │  ┌─────────────────────────────────────────────────────────────────┐    │
 │  │                    WORKING MEMORY (Scratchpad)                   │    │
 │  │                                                                 │    │
 │  │  ┌───────────────────────────────────────────────────┐           │    │
 │  │  │ Current reasoning trace (Thought₁→Act₁→Obs₁...)   │           │    │
 │  │  │ Active plan steps                                  │           │    │
 │  │  │ Pending tool results                               │           │    │
 │  │  │ Context window (token-limited)                    │           │    │
 │  │  └───────────────────────────────────────────────────┘           │    │
 │  │                                                                 │    │
 │  │  Lifecycle: Created fresh each session, evaporates on completion     │    │
 │  │  Capacity: Bounded by context window (4K–200K tokens)            │    │
 │  └──────────────────────────────┬──────────────────────────────────┘    │
 │                                 │                                       │
 │                  ┌──────────────┼──────────────┐                        │
 │                  ▼              ▼              ▼                        │
 │  ┌──────────────────┐ ┌───────────────────┐ ┌───────────────────┐      │
 │  │  SHORT-TERM      │ │  EPISODIC         │ │  SEMANTIC         │      │
 │  │  MEMORY           │ │  MEMORY           │ │  MEMORY           │      │
 │  │                  │ │                   │ │                   │      │
 │  │  Recent N turns  │ │  Past trajectory  │ │  Abstracted       │      │
 │  │  of conversation │ │  logs with        │ │  knowledge,       │      │
 │  │  or interaction  │ │  outcomes and    │ │  facts, rules,    │      │
 │  │                  │ │  lessons learned  │ │  patterns         │      │
 │  │  Retention:     │ │                   │ │                   │      │
 │  │  Minutes to     │ │  Retention:       │ │  Retention:       │      │
 │  │  hours          │ │  Days to weeks    │ │  Permanent        │      │
 │  │                  │ │                   │ │                   │      │
 │  │  Storage:       │ │  Storage:         │ │  Storage:         │      │
 │  │  In-context     │ │  Log files,       │ │  Vector store,    │      │
 │  │  window         │ │  structured DB    │ │  knowledge graph   │      │
 │  └──────────────────┘ └───────────────────┘ └───────────────────┘      │
 │                                                                          │
 │  ┌──────────────────────────────────────────────────────────────────┐    │
 │  │                     LONG-TERM MEMORY                             │    │
 │  │                                                                  │    │
 │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐    │    │
 │  │  │ Vector Store │  │ Knowledge    │  │ Relational DB         │    │    │
 │  │  │              │  │ Graph        │  │                       │    │    │
 │  │  │ Embedding-   │  │ Entity-      │  │ Structured facts,     │    │    │
 │  │  │ based        │  │ relationship │  │ user preferences,     │    │    │
 │  │  │ semantic     │  │ triples      │  │ configuration data    │    │    │
 │  │  │ search       │  │              │  │                       │    │    │
 │  │  │              │  │  (User)──    │  │  ┌──────────────────┐ │    │    │
 │  │  │  [0.12,      │  │    likes──▶  │  │  │ user_id | pref   │ │    │    │
 │  │  │   0.45,      │  │  (Product)   │  │  │ 1       | concise│ │    │    │
 │  │  │   0.78, ...] │  │              │  │  │ 2       | detail │ │    │    │
 │  │  └──────────────┘  └──────────────┘  │  └──────────────────┘ │    │    │
 │  │                                       └──────────────────────┘    │    │
 │  │  Retrieval: Similarity search + re-ranking + recency weighting     │    │
 │  │  Write-back: Consolidation after reflection events                  │    │
 │  └──────────────────────────────────────────────────────────────────┘    │
 └──────────────────────────────────────────────────────────────────────────┘
```

### Memory Types in Detail

**Working Memory** is the agent's scratchpad—the current chain of thought, active plan, and recent observations. It exists within the LLM's context window and is the most expensive memory per token. When the context window fills, older content must be summarized or evicted.

**Short-Term Memory** covers the last few conversation turns. It is typically managed as a sliding window or a recency-weighted buffer that keeps recent interactions prominent while gradually decaying older ones.

**Episodic Memory** records *specific experiences*: what the agent did, what happened, and what the outcome was. It answers questions like "last time I tried this approach, what happened?" Episodic memory includes timestamps, context, actions taken, and results achieved.

**Semantic Memory** stores abstracted knowledge: facts, rules, patterns, and relationships distilled from experience. It answers "what do I know about X?" Semantic memory is built through **consolidation**—the process of reflecting on episodic memories and extracting generalizable knowledge.

### Memory Operations

| Operation | Description | Example |
|---|---|---|
| **Encode** | Store new information | Save tool result to working memory |
| **Retrieve** | Recall relevant information | Semantic search for related past solutions |
| **Consolidate** | Transfer from short-term to long-term | Summarize session learnings to knowledge base |
| **Forget** | Decay or remove outdated info | Evict low-relevance memories under capacity pressure |
| **Update** | Modify existing memory | Correct a fact after receiving new evidence |

---

## 7. Agent Loops and Control Flow

The agent loop is the fundamental execution pattern of agentic AI. It is a cyclic process of observing, thinking, and acting until a termination condition is met.

### Agent Control Flow — Full Diagram

```
 ┌───────────────────────────────────────────────────────────────────────┐
 │                      AGENT CONTROL FLOW                               │
 │                                                                       │
 │  ┌─────────────┐                                                     │
 │  │  INITIALIZATION│                                                   │
 │  │             │                                                     │
 │  │ • Load goal │                                                     │
 │  │ • Load tools│                                                     │
 │  │ • Load rules│                                                     │
 │  │ • Reset     │                                                     │
 │  │   scratchpad│                                                     │
 │  └──────┬──────┘                                                     │
 │         │                                                             │
 │         ▼                                                             │
 │  ┌──────────────────────────────┐                                    │
 │  │  CHECK PRECONDITIONS         │                                    │
 │  │                              │                                    │
 │  │  • Is the goal well-formed?  │──── No ──▶ CLARIFY with user       │
 │  │  • Are tools available?      │         │                           │
 │  │  • Safety constraints OK?    │         ▼                           │
 │  └──────────────┬───────────────┘    Refine goal                       │
 │                 │                     │                                │
 │                 │ Yes                 │                                │
 │                 ▼                     │                                │
 │         ┌──────────────┐              │                                │
 │         │  PLAN         │◀─────────────┘                                │
 │         │              │                                               │
 │         │ Decompose    │                                               │
 │         │ goal into    │                                               │
 │         │ sub-steps    │                                               │
 │         └──────┬───────┘                                               │
 │                │                                                       │
 │       ┌────────▼──────────────────────────────────────────┐           │
 │       │           ◀──── MAIN AGENT LOOP ────▶              │           │
 │       │                                                    │           │
 │       │  ┌──────────────────────────────────────────────┐  │           │
 │       │  │         STEP 1: OBSERVE                      │  │           │
 │       │  │                                              │  │           │
 │       │  │  • Read environment state                    │  │           │
 │       │  │  • Collect tool results from previous action │  │           │
 │       │  │  • Parse user messages                       │  │           │
 │       │  │  • Update working memory                    │  │           │
 │       │  └──────────────────┬───────────────────────────┘  │           │
 │       │                     │                               │           │
 │       │                     ▼                               │           │
 │       │  ┌──────────────────────────────────────────────┐  │           │
 │       │  │         STEP 2: THINK                         │  │           │
 │       │  │                                              │  │           │
 │       │  │  • Analyze current situation                 │  │           │
 │       │  │  • Retrieve relevant memories                │  │           │
 │       │  │  • Evaluate progress toward goal             │  │           │
 │       │  │  • Consider alternative approaches           │  │           │
 │       │  │  • Decide: act or finish?                    │  │           │
 │       │  └──────────────────┬───────────────────────────┘  │           │
 │       │                     │                               │           │
 │       │          ┌──────────┴──────────┐                   │           │
 │       │          │                     │                   │           │
 │       │          ▼                     ▼                   │           │
 │       │    ┌───────────┐       ┌───────────────┐          │           │
 │       │    │ Goal met? │       │ Stuck / error │          │           │
 │       │    │ (success) │       │ detected?     │          │           │
 │       │    └─────┬─────┘       └──────┬────────┘          │           │
 │       │          │                    │                     │           │
 │       │       Yes │                Yes │                    │           │
 │       │          │                    │                     │           │
 │       │          │                    ▼                     │           │
 │       │          │           ┌─────────────────┐           │           │
 │       │          │           │  REFLECT &       │           │           │
 │       │          │           │  REPLAN           │           │           │
 │       │          │           │                   │           │           │
 │       │          │           │  • Diagnose error │           │           │
 │       │          │           │  • Revise plan    │           │           │
 │       │          │           │  • Try new approach│          │           │
 │       │          │           └────────┬──────────┘           │           │
 │       │          │                    │                       │           │
 │       │          │                    │ (continue loop)       │           │
 │       │          │                    └───────────┐           │           │
 │       │          │                                │           │           │
 │       │          ▼                                │           │           │
 │       │  ┌─────────────────────────────────┐     │           │           │
 │       │  │    STEP 3: ACT                   │     │           │           │
 │       │  │                                 │     │           │           │
 │       │  │  • Select tool                  │     │           │           │
 │       │  │  • Construct arguments           │     │           │           │
 │       │  │  • Apply safety checks ──▶ BLOCK │     │           │           │
 │       │  │    if unsafe                    │     │           │           │
 │       │  │  • Execute tool                 │     │           │           │
 │       │  │  • Capture result               │     │           │           │
 │       │  │  • Rate limit / retry            │◀────┘           │           │
 │       │  └───────────────┬─────────────────┘                  │           │
 │       │                  │                                     │           │
 │       │                  └─────── (loop back to OBSERVE) ─────┘           │
 │       │                                                                  │
 │       └──────────────────────────────────────────────────────────────────┘
 │                │
 │                ▼
 │       ┌────────────────┐
 │       │  TERMINATE      │
 │       │                 │
 │       │  • Return final │
 │       │    answer       │
 │       │  • Store session │
 │       │    to episodic  │
 │       │    memory       │
 │       │  • Consolidate  │
 │       │    learnings    │
 │       └─────────────────┘
 └───────────────────────────────────────────────────────────────────────┘
```

### Termination Conditions

An agent loop terminates when **any** of these conditions are met:

1. **Goal achieved**: The agent's output satisfies the success criteria.
2. **Max iterations**: A safety limit prevents infinite loops (e.g., 25 steps).
3. **Max tokens**: Cumulative token usage exceeds a budget.
4. **Explicit finish**: The agent emits a special `finish` action.
5. **User interrupt**: The user explicitly halts execution.
6. **Error budget exceeded**: Too many consecutive tool failures trigger a blanket halt.

### Defensive Loop Patterns

- **Deduplication**: If the agent produces the same action twice consecutively, break the loop or force replanning.
- **Progress checks**: Every N steps, verify that the agent is making measurable progress toward the goal.
- **Resource budgets**: Set per-tool and per-session cost/time limits.

---

## 8. Prompt Engineering for Agents

Prompt engineering for agentic systems is fundamentally different from prompting for single-turn tasks. The system prompt must define not just the task, but the **persona**, **behavioral constraints**, **tool usage norms**, and **decision-making heuristics** the agent should follow.

### System Prompt Structure

```
┌─────────────────────────────────────────────────────────────────┐
 │                    AGENT SYSTEM PROMPT ANATOMY                  │
 │                                                                │
 │  ┌─────────────────────────────────────────────────────────┐  │
 │  │  1. IDENTITY AND ROLE                                    │  │
 │  │     Who you are, what you do, your expertise domain      │  │
 │  └─────────────────────────────────────────────────────────┘  │
 │  ┌─────────────────────────────────────────────────────────┐  │
 │  │  2. BEHAVIORAL RULES                                     │  │
 │  │     How you should act, what to prioritize, what to avoid │  │
 │  └─────────────────────────────────────────────────────────┘  │
 │  ┌─────────────────────────────────────────────────────────┐  │
 │  │  3. TOOL DESCRIPTIONS                                    │  │
 │  │     Available tools, when to use each, parameters         │  │
 │  └─────────────────────────────────────────────────────────┘  │
 │  ┌─────────────────────────────────────────────────────────┐  │
 │  │  4. OUTPUT FORMAT                                        │  │
 │  │     Expected response structure (JSON, markdown, etc.)    │  │
 │  └─────────────────────────────────────────────────────────┘  │
 │  ┌─────────────────────────────────────────────────────────┐  │
 │  │  5. SAFETY CONSTRAINTS                                   │  │
 │  │     Hard boundaries on behavior and tool use              │  │
 │  └─────────────────────────────────────────────────────────┘  │
 │  ┌─────────────────────────────────────────────────────────┐  │
 │  │  6. REASONING INSTRUCTIONS                               │  │
 │  │     How to think through problems step-by-step            │  │
 │  └─────────────────────────────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────────┘
```

### Example System Prompt

```markdown
You are a research assistant specialized in scientific literature review.

## Identity
You help users find, analyze, and synthesize academic papers. You are thorough,
precise, and always cite your sources.

## Behavioral Rules
- Always verify claims with evidence from at least two sources.
- When uncertain, say so explicitly rather than guessing.
- Break complex research questions into sub-questions.
- Summarize findings before diving into details.

## Tool Usage
- `search_papers(query)`: Search academic databases. Use when you need to find
  papers on a topic.
- `read_paper(url)`: Extract full text from a paper. Use after search to get
  details.
- `compare_findings(paper_ids)`: Cross-reference claims across papers. Use when
  synthesizing multiple sources.

## Reasoning Process
For each step, explicitly state:
1. What you currently know
2. What information you still need
3. Which tool you will use and why
4. What you learned from the result

## Safety
- Never fabricate citations or paper titles.
- Do not access non-academic sources without user approval.
- If a query involves medical advice, include a disclaimer.
```

### Key Prompt Design Principles for Agents

1. **Be explicit about decision thresholds**: "Use `search` when you lack specific factual information" is better than "Use tools when needed."
2. **Define failure modes**: Tell the agent what to do when a tool returns an error or empty result.
3. **Constrain scope**: Clearly state what the agent should NOT do.
4. **Specify the reasoning format**: ReAct (`Thought: ... Action: ... Observation: ...`), or structured JSON, or any consistent format.
5. **Include meta-instructions**: "If you find yourself repeating the same action, stop and reconsider your approach."

---

## 9. Safety and Guardrails

Agent safety is about preventing **intended misuse**, **unintended harm**, and **runaway behavior**. Because agents can take real actions in the world (API calls, code execution, financial transactions), safety is not optional—it is an architectural requirement.

### Safety Guardrails Architecture

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    SAFETY GUARDRAILS ARCHITECTURE                      │
 │                                                                        │
 │  ┌─────────────────────────────────────────────────────────────────┐  │
 │  │                    INPUT VALIDATION LAYER                        │  │
 │  │                                                                 │  │
 │  │  ┌──────────┐  ┌──────────────┐  ┌────────────┐  ┌──────────┐  │  │
 │  │  │ Prompt   │  │ Intent       │  │ Injection  │  │ Scope    │  │  │
 │  │  │ filter   │  │ classifier  │  │ detector   │  │ enforcer │  │  │
 │  │  │          │  │              │  │            │  │          │  │  │
 │  │  │ Blocks   │  │ Classifies   │  │ Detects    │  │ Ensures │  │  │
 │  │  │ harmful  │  │ user intent  │  │ prompt     │  │ request  │  │  │
 │  │  │ user     │  │ (benign,    │  │ injection  │  │ is within│  │  │
 │  │  │ requests │  │  ambiguous, │  │ attempts   │  │ allowed  │  │  │
 │  │  │          │  │  harmful)   │  │            │  │ domain   │  │  │
 │  │  └──────────┘  └──────────────┘  └────────────┘  └──────────┘  │  │
 │  └─────────────────────────────────────────────────────────────────┘  │
 │                                 │                                     │
 │                                 ▼                                     │
 │  ┌─────────────────────────────────────────────────────────────────┐  │
 │  │                    REASONING MONITOR LAYER                       │  │
 │  │                                                                 │  │
 │  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │  │
 │  │  │ Loop         │  │ Budget       │  │ Goal alignment         │  │  │
 │  │  │ detector     │  │ enforcer     │  │ checker                 │  │  │
 │  │  │              │  │              │  │                        │  │  │
 │  │  │ Detects      │  │ Caps max     │  │ Verifies each          │  │  │
 │  │  │ repetitive   │  │ iterations,  │  │ reasoning step          │  │  │
 │  │  │ or circular │  │ tokens, and  │  │ is still moving        │  │  │
 │  │  │ reasoning   │  │ cost per     │  │ toward the             │  │  │
 │  │  │ patterns    │  │ session      │  │ original goal          │  │  │
 │  │  └──────────────┘  └──────────────┘  └───────────────────────┘  │  │
 │  └─────────────────────────────────────────────────────────────────┘  │
 │                                 │                                     │
 │                                 ▼                                     │
 │  ┌─────────────────────────────────────────────────────────────────┐  │
 │  │                    ACTION MODERATION LAYER                       │  │
 │  │                                                                 │  │
 │  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │  │
 │  │  │ Action       │  │ Rate         │  │ Permission             │  │  │
 │  │  │ classifier  │  │ limiter      │  │ boundary               │  │  │
 │  │  │              │  │              │  │                        │  │  │
 │  │  │ Classifies   │  │ Enforces    │  │ Maps each tool         │  │  │
 │  │  │ each action │  │ cooldowns,  │  │ to an allowed          │  │  │
 │  │  │ as safe /   │  │ concurrency │  │ action set per         │  │  │
 │  │  │ unsafe /    │  │ limits, and │  │ role / context         │  │  │
 │  │  │ needs-      │  │ max calls  │  │                        │  │  │
 │  │  │ approval    │  │ per tool   │  │ (read-only vs.         │  │  │
 │  │  │             │  │             │  │  read-write vs.       │  │  │
 │  │  │             │  │             │  │  destructive)          │  │  │
 │  │  └──────────────┘  └──────────────┘  └───────────────────────┘  │  │
 │  └─────────────────────────────────────────────────────────────────┘  │
 │                                 │                                     │
 │                                 ▼                                     │
 │  ┌─────────────────────────────────────────────────────────────────┐  │
 │  │                    OUTPUT VALIDATION LAYER                       │  │
 │  │                                                                 │  │
 │  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │  │
 │  │  │ Content      │  │ PII          │  │ Hallucination          │  │  │
 │  │  │ filter       │  │ scrubber    │  │ checkpoint             │  │  │
 │  │  │              │  │              │  │                        │  │  │
 │  │  │ Removes      │  │ Detects and │  │ Requires agent to     │  │  │
 │  │  │ harmful,    │  │ masks       │  │ cite sources for     │  │  │
 │  │  │ biased, or  │  │ personally  │  │ factual claims       │  │  │
 │  │  │ inappropriate│  │ identifiable│  │ and flag uncertain   │  │  │
 │  │  │ content     │  │ information │  │ information          │  │  │
 │  │  └──────────────┘  └──────────────┘  └───────────────────────┘  │  │
 │  └─────────────────────────────────────────────────────────────────┘  │
 └────────────────────────────────────────────────────────────────────────┘
```

### Safety Principles for Agentic Systems

1. **Principle of Least Privilege**: Grant tools the minimum permissions needed. A research agent should not have write access to production databases.
2. **Fail-Safe Defaults**: When in doubt, block the action and escalate to a human.
3. **Auditability**: Every action, thought, and observation should be logged immutably for post-hoc analysis.
4. **Containment**: Sandbox tool execution. Code should run in isolated containers; API calls should go through rate-limited proxies.
5. **Human-in-the-Loop**: For high-stakes actions (deletions, financial transactions, irreversible changes), require explicit human approval before execution.

---

## 10. Reflection and Self-Correction

Reflection is the mechanism by which an agent monitors and improves its own reasoning and behavior. Without reflection, an agent can only move forward; with it, the agent can recognize errors, learn from them, and adapt.

### Reflection Mechanisms

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                 REFLECTION & SELF-CORRECTION MECHANISMS                │
 │                                                                        │
 │   ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐       │
 │   │  ACT    │────▶│ OBSERVE │────▶│ REFLECT │────▶│ REVISE  │       │
 │   │         │     │ RESULT  │     │         │     │ PLAN    │       │
 │   └─────────┘     └─────────┘     └────┬────┘     └────┬────┘       │
 │                                       │               │              │
 │                                       │               │              │
 │  ┌────────────────────────────────────▼───────────────▼──────────┐  │
 │  │                    REFLECTION TYPES                             │  │
 │  │                                                                 │  │
 │  │  ┌──────────────────────────────────────────────────────────┐  │  │
 │  │  │  1. ACTION-LEVEL REFLECTION                               │  │  │
 │  │  │     "That tool call returned an error. Let me try        │  │  │
 │  │  │      a different query."                                   │  │  │
 │  │  │     → Immediate, localized, within the current step       │  │  │
 │  │  └──────────────────────────────────────────────────────────┘  │  │
 │  │                                                                 │  │
 │  │  ┌──────────────────────────────────────────────────────────┐  │  │
 │  │  │  2. STRATEGY-LEVEL REFLECTION                             │  │  │
 │  │  │     "I've searched three times but keep finding the       │  │  │
 │  │  │      same information. Maybe I should approach this       │  │  │
 │  │  │      from a different angle—try a different source."      │  │  │
 │  │  │     → Broader, re-examines the approach/plan              │  │  │
 │  │  └──────────────────────────────────────────────────────────┘  │  │
 │  │                                                                 │  │
 │  │  ┌──────────────────────────────────────────────────────────┐  │  │
 │  │  │  3. EPISTEMIC REFLECTION                                  │  │  │
 │  │  │     "I'm not confident in this answer. The sources        │  │  │
 │  │  │      conflict, and I don't have enough evidence.          │  │  │
 │  │  │      I should flag this uncertainty in my response."      │  │  │
 │  │  │     → Metacognitive, assesses certainty and knowledge    │  │  │
 │  │  └──────────────────────────────────────────────────────────┘  │  │
 │  │                                                                 │  │
 │  │  ┌──────────────────────────────────────────────────────────┐  │  │
 │  │  │  4. CONSOLIDATION REFLECTION                              │  │  │
 │  │  │     "Across this session, I learned that API X is         │  │  │
 │  │  │      unreliable on weekends. I should save this           │  │  │
 │  │  │      to long-term memory."                                │  │  │
 │  │  │     → Post-session, extracts generalizable knowledge      │  │  │
 │  │  └──────────────────────────────────────────────────────────┘  │  │
 │  └─────────────────────────────────────────────────────────────────┘  │
 └────────────────────────────────────────────────────────────────────────┘
```

### Reflection in Practice

**Self-critique prompting**: After generating an initial response, ask the agent to critique its own answer:

```
Initial response: [agent's first attempt]
Critique prompt: "Review your previous answer. Identify any errors,
unsupported claims, or missing considerations. Then provide an improved answer."
Improved response: [agent's revised answer]
```

**Success-based reflection**: When an action succeeds, reflect on *why* it worked to reinforce effective strategies:

```
Observation: Tool call succeeded with expected result.
Reflection: "The search query 'renewable energy policy EU 2024' was specific
enough to surface relevant results. For future searches on policy topics,
including both the domain and year improves precision."
```

**Failure-based reflection**: When an action fails, diagnose the root cause and update the approach:

```
Observation: Tool call returned HTTP 429 (rate limited).
Reflection: "I've made too many API calls in a short period. I should batch
my requests, add delays between calls, or use a different data source that
isn't rate-limited."
```

### Reflection Triggers

| Trigger | Response |
|---|---|
| Tool returns error | Action-level reflection → retry with different args |
| Repeated failed attempts (>N) | Strategy-level reflection → change approach entirely |
| Contradictory information | Epistemic reflection → flag uncertainty, seek more sources |
| Goal completion | Consolidation reflection → extract lessons for long-term memory |
| Human correction | Immediate reflection → adjust behavior, store correction |

---

## 11. The Autonomy Spectrum

Not all agents are equally autonomous. The level of autonomy determines how much human oversight is required and how much the agent can decide on its own.

### Autonomy Spectrum Diagram

```
 ┌────────────────────────────────────────────────────────────────────────────┐
 │                         AUTONOMY SPECTRUM                                  │
 │                                                                            │
 │  ◀─────────────────────────────────────────────────────────────────────▶   │
 │  LOW AUTONOMY                                              HIGH AUTONOMY  │
 │                                                                            │
 │  ┌──────────────┐  ┌───────────────┐  ┌──────────────┐  ┌─────────────┐  │
 │  │   TOOL-USING  │  │  TASK-DRIVEN   │  │  GOAL-DRIVEN │  │   FULLY     │  │
 │  │    AGENT      │  │    AGENT       │  │    AGENT     │  │  AUTONOMOUS │  │
 │  │              │  │               │  │              │  │             │  │
 │  │  Human gives │  │  Human gives  │  │  Human gives │  │  Human gives│  │
 │  │  exact tool  │  │  a specific   │  │  a high-level│  │  a high-level│  │
 │  │  invocations │  │  task; agent  │  │  goal; agent │  │  goal; agent│  │
 │  │  to execute  │  │  decides how  │  │  decides what│  │  decides   │  │
 │  │              │  │  to accomplish│  │  sub-goals   │  │  goal scope│  │
 │  │              │  │  it           │  │  are needed  │  │  & strategy │  │
 │  │              │  │               │  │  & how to    │  │  & whether │  │
 │  │              │  │               │  │  achieve them│  │  to proceed│  │
 │  └──────┬───────┘  └───────┬───────┘  └──────┬───────┘  └──────┬──────┘  │
 │         │                  │                 │                 │          │
 │         ▼                  ▼                 ▼                 ▼          │
 │  ┌──────────────┐  ┌───────────────┐  ┌──────────────┐  ┌─────────────┐  │
 │  │ EXAMPLE:     │  │ EXAMPLE:      │  │ EXAMPLE:     │  │ EXAMPLE:   │  │
 │  │              │  │               │  │              │  │             │  │
 │  │ "Search for  │  │ "Research     │  │ "Write an    │  │ "Explore   │  │
 │  │  GPT-4       │  │  competitive  │  │  app that   │  │  the market│  │
 │  │  benchmarks" │  │  landscape    │  │  automates  │  │  and build │  │
 │  │              │  │  for code     │  │  our CI/CD  │  │  whatever  │  │
 │  │ → Uses search│  │  assistants"  │  │  pipeline"  │  │  product   │  │
 │  │   tool once  │  │               │  │              │  │  will win  │  │
 │  │              │  │ → Plans the   │  │ → Decomposes│  │             │  │
 │  │ → Returns    │  │   research,   │  │   into:     │  │ → Defines  │  │
 │  │   result     │  │   selects     │  │  design,    │  │   own OKRs │  │
 │  │              │  │   sources,     │  │  implement, │  │   scope    │  │
 │  │              │  │   synthesizes │  │  test,      │  │   audience │  │
 │  │              │  │   a report    │  │  deploy      │  │   strategy │  │
 │  └──────────────┘  └───────────────┘  └──────────────┘  └─────────────┘  │
 │                                                                            │
 │  ┌──────────────────────────────────────────────────────────────────────┐ │
 │  │                  AUTONOMY DIMENSIONS                                 │ │
 │  │                                                                      │ │
 │  │  Dimension        │ Tool-using │ Task-driven │ Goal-driven │ Fully   │ │
 │  │───────────────────┼────────────┼─────────────┼──────────────┼────────│ │
 │  │  Goal setting     │ Human      │ Human       │ Human        │ Agent  │ │
 │  │  Sub-goal decomp  │ None       │ Human       │ Agent        │ Agent  │ │
 │  │  Tool selection   │ Human      │ Agent       │ Agent        │ Agent  │ │
 │  │  Plan creation    │ None       │ Agent       │ Agent        │ Agent  │ │
 │  │  Plan revision    │ None       │ Human       │ Agent        │ Agent  │ │
 │  │  Error recovery   │ Human      │ Agent+Human │ Agent        │ Agent  │ │
 │  │  Scope definition │ Human      │ Human       │ Human+Agent  │ Agent  │ │
 │  │  Stop condition   │ Human      │ Human       │ Agent+Human  │ Agent  │ │
 │  │  Safety oversight │ Human      │ Human       │ Human        │ ???    │ │
 │  └──────────────────────────────────────────────────────────────────────┘ │
 └────────────────────────────────────────────────────────────────────────────┘
```

### When to Use Each Level

**Tool-using agents** are appropriate when the task is simple and well-defined. The human knows exactly what information or action they need, and just wants the agent to execute it efficiently. Example: a search-augmented chatbot.

**Task-driven agents** are appropriate when the *what* is clear but the *how* is complex. The user specifies a concrete deliverable, and the agent plans the execution path. Example: a research assistant that produces a literature review.

**Goal-driven agents** are appropriate when the *what* itself requires judgment to decompose. The user provides a high-level objective, and the agent must identify useful sub-goals, pursue them, and integrate results. Example: a software engineer agent that designs, builds, and tests a feature.

**Fully autonomous agents** are appropriate only in well-bounded domains where the agent has sufficient expertise and the cost of errors is low. Safety oversight remains essential. Example: a monitoring agent that detects anomalies, investigates root causes, and applies pre-approved remediation scripts.

### Increasing Autonomy Safely

Moving up the autonomy spectrum requires progressively stronger safety mechanisms:

1. **Tool-using**: Input validation only.
2. **Task-driven**: Input validation + action approval for high-risk tools.
3. **Goal-driven**: All the above + goal alignment checking + human approval at decision points.
4. **Fully autonomous**: All the above + continuous monitoring + kill switches + consent frameworks + regular human review.

The key principle: **the broader the agent's decision space, the tighter the guardrails must be.**

---

## Appendix: Cross-Reference Map

```
 Component        │ Depends On              │ Feeds Into
──────────────────┼─────────────────────────┼──────────────────────────────
 Perception       │ Environment, Tools       │ Working Memory, Reasoner
 Reasoning        │ Working Memory, Goals     │ Plan, Action Selection
 Planning         │ Reasoner, Long-term Mem  │ Action Sequence
 Action           │ Reasoner, Plan            │ Environment, Observations
 Working Memory   │ Perception, Reasoning    │ Reasoner (next step)
 Long-term Memory │ Reflection, Consolidation│ Planning, Reasoner
 Reflection       │ Observation + Reasoning  │ Plan Revision, Memory Update
 Safety           │ All actions (intercept)  │ Action Approval, Logging
 Tools            │ Action Executor           │ Environment, Observations
```

---

*This document covers the theoretical foundations of agentic AI. For implementation patterns, framework comparisons, and production deployment guidance, see the companion sections in this series.*

## Real References

1. Yao, S., Zhao, J., Yu, D., Du, N., Shafran, I., Narasimhan, K., & Cao, Y. "ReAct: Synergizing Reasoning and Acting in Language Models." *ICLR 2023*. arXiv:2210.03629. https://arxiv.org/abs/2210.03629

2. Wei, J., Wang, X., Schuurmans, D., Bosma, M., Xia, F., Chi, E., Le, Q. V., & Zhou, D. "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models." *NeurIPS 2022*. arXiv:2201.11903. https://arxiv.org/abs/2201.11903

3. Yao, S., Yu, D., Zhao, J., Shafran, I., Griffiths, T. L., Cao, Y., & Narasimhan, K. "Tree of Thoughts: Deliberate Problem Solving with Large Language Models." *NeurIPS 2023*. arXiv:2305.10601. https://arxiv.org/abs/2305.10601

4. Besta, M., Blach, N., Kubicek, A., Gerstenberger, R., Podstawski, M., Gajda, A., Niewiadomski, A., & Hoefler, T. "Graph of Thoughts: Solving Elaborate Problems with Large Language Models." *AAAI 2024*. arXiv:2308.09687. https://arxiv.org/abs/2308.09687

5. Wang, X., Wei, J., Schuurmans, D., Le, Q., Chi, E., Narang, S., Chowdhery, A., & Zhou, D. "Self-Consistency Improves Chain of Thought Reasoning in Language Models." *ICML 2023*. arXiv:2203.11171. https://arxiv.org/abs/2203.11171

6. Shinn, N., Cassano, F., Gopinath, A., Narasimhan, K., & Yao, S. "Reflexion: Language Agents with Verbal Reinforcement Learning." *NeurIPS 2023*. arXiv:2303.11366. https://arxiv.org/abs/2303.11366

7. Zhou, D., Schärli, N., Hou, L., Wei, J., Scales, N., Wang, X., Schuurmans, D., Cui, C., Bousquet, O., Le, Q., & Chi, E. "Least-to-Most Prompting Enables Complex Reasoning in Large Language Models." *ICLR 2023*. arXiv:2205.10625. https://arxiv.org/abs/2205.10625

8. Schick, T., Dwivedi-Yu, J., Dessi, R., Raileanu, R., Lomeli, M., Hambro, E., Zettlemoyer, L., Cancedda, N., & Scialom, T. "Toolformer: Language Models Can Teach Themselves to Use Tools." *NeurIPS 2023*. arXiv:2302.04761. https://arxiv.org/abs/2302.04761

9. Mialon, G., Dessi, R., Lomeli, M., Nair, C., Gresik-Schatz, A., Wolf, T., & Scialom, T. "Augmented Language Models: a Survey." *TMLR 2023*. arXiv:2302.07842. https://arxiv.org/abs/2302.07842

10. OpenAI. "GPT-4 Technical Report." arXiv:2303.08774. https://arxiv.org/abs/2303.08774

11. Anthropic. "Building Effective Agents." https://www.anthropic.com/research/building-effective-agents

12. Yao, S., Yu, D., Zhao, J., Shafran, I., Griffiths, T. L., Cao, Y., & Narasimhan, K. "Tree of Thoughts: Deliberate Problem Solving with Large Language Models." *NeurIPS 2023*. arXiv:2305.10601

13. Wang, L., Xu, W., Lan, Y., Hu, Z., Lan, Y., Lee, R. K.-W., & Lim, E.-P. "Plan-and-Solve Prompting: Improving Zero-Shot Chain-of-Thought Reasoning by Large Language Models." *ACL 2023*. arXiv:2305.04091. https://arxiv.org/abs/2305.04091

14. Madaan, A., Tandon, N., Gupta, P., Hallinan, S., Gao, L., Wiegreffe, S., Alon, U., Dziri, N., Prabhumoye, S., Yang, Y., others "Self-Refine: Iterative Refinement with Self-Feedback." *NeurIPS 2023*. arXiv:2303.17651. https://arxiv.org/abs/2303.17651

15. Shinn, N., Cassano, F., Gopinath, A., Narasimhan, K., & Yao, S. "Reflexion: Language Agents with Verbal Reinforcement Learning." *NeurIPS 2023*. arXiv:2303.11366

16. Khot, T., Trivedi, H., Finlayson, M., Fu, X., Richardson, K., Clark, P., & Sabharwal, A. "Decomposed Prompting: A Modular Approach for Solving Complex Tasks." *ICLR 2023*. arXiv:2210.02406. https://arxiv.org/abs/2210.02406

17. Significant Gravitas. "AutoGPT: An Autonomous GPT-4 Experiment." https://github.com/Significant-Gravitas/AutoGPT (2023).

18. Richards, T. "AutoGPT: The Dawn of Autonomous AI Agents." *Medium / Toward Data Science*, 2023.

19. Park, J. S., O'Brien, J. C., Cai, C., Morris, M. R., Liang, P., & Bernstein, M. S. "Generative Agents: Interactive Simulacra of Human Behavior." *UIST 2023*. arXiv:2304.03442. https://arxiv.org/abs/2304.03442

20. Hao, S., Liu, T., Wang, Z., Hu, Z., Fu, J., Mei, J., & Valiant, G. "Tool Learning with Foundation Models." *IEEE Intelligent Systems*, 2024. arXiv:2304.08354. https://arxiv.org/abs/2304.08354

21. Qin, Y., Liang, S., Ye, Y., Zhu, K., Yan, L., Lu, Y., Lin, Y., Cong, X., Tang, X., Qian, B., Zhao, S., Hong, L., Liu, Z., & Sun, M. "ToolBench: A Large Language Model-Based Tool Learning Benchmark." *ICLR 2024*. arXiv:2307.16789. https://arxiv.org/abs/2307.16789

22. Liu, X., Yan, H., Zhang, C., Hou, Y., Huang, R., Shen, J., Zhang, X., & Sun, M. "Retrieval-Augmented Generation for AI-Generated Content: A Survey." *Foundations and Trends in Information Retrieval*, 2024. arXiv:2402.19473. https://arxiv.org/abs/2402.19473

23. Lewis, P., Perez, E., Piktus, A., Petroni, F., Karpukhin, V., Goyal, N., Kütting, H., Lewis, M., Yen, W.-t., Rocktäschel, T., Kiela, D., & Strubell, E. "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks." *NeurIPS 2020*. arXiv:2005.11401. https://arxiv.org/abs/2005.11401

24. Guu, K., Lee, K., Tung, Z., Parmar, N., & Chang, M.-W. "Retrieval Augmented Language Model Pre-Training." *ICML 2020*. https://proceedings.mlr.press/v119/guu20a.html

25. Kwon, W., Li, Z., Zhuang, S., Sheng, Y., Zheng, L., Yu, C. H., Gonzalez, J. E., Zhang, H., & Stoica, I. "Efficient Memory Management for Large Language Model Serving with PagedAttention." *SOSP 2023*. arXiv:2309.06180. https://arxiv.org/abs/2309.06180

26. Wu, Q., Bansal, G., Zhang, J., Wu, Y., Li, B., Zhu, E., Jiang, L., Zhang, X., Zhang, S., Liu, J., Awadallah, A. H., Lewis, R., Wang, W., & Xie, Y. "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation." *COLM 2024*. arXiv:2308.08155. https://arxiv.org/abs/2308.08155

27. Hong, S., Zhuge, M., Chen, J., Zheng, X., Cheng, Y., Zhang, C., & Wang, J. "MetaGPT: Meta Programming for Multi-Agent Collaborative Framework." *ICLR 2024*. arXiv:2308.00352. https://arxiv.org/abs/2308.00352

28. Talebirad, Y., & Nadiri, A. "Multi-Agent Collaboration: Harnessing the Power of Intelligent LLM Agents." *AAAI 2023 Spring Symposium*. arXiv:2307.04964. https://arxiv.org/abs/2307.04964

29. Wang, L., Ma, C., Feng, X., Zhang, Z., Yang, H., Zhang, J., Chen, Z., Tang, J., Chen, X., Lin, Y., Zhao, W., Wei, Z., & Zhang, J. "A Survey on Large Language Model Based Autonomous Agents." *Frontiers of Computer Science*, 2024. arXiv:2308.11432. https://arxiv.org/abs/2308.11432

30. Xi, Z., Chen, W., Guo, X., He, W., Ding, Y., Hong, B., Zhang, M., & Wang, J. "The Rise and Potential of Large Language Model Based Agents: A Survey." *Intelligent Computing*, 2023. arXiv:2309.07864. https://arxiv.org/abs/2309.07864

31. Masterman, T., Besen, S., Sawtell, M., & Chao, A. "The Landscape of Emerging AI Agent Architectures for Reasoning, Planning, and Decision Making." *arXiv preprint*, 2024. arXiv:2404.11528. https://arxiv.org/abs/2404.11528

32. Nakano, R., et al. "WebGPT: Browser-Assisted Question-Answering with Human Feedback." *arXiv preprint*, 2021. arXiv:2112.09332. https://arxiv.org/abs/2112.09332

33. Gao, L., Madaan, A., Zhou, S., Alon, U., Liu, P., Yang, Y., Callan, J., & Neubig, G. "PAL: Program-Aided Language Models." *ICML 2023*. arXiv:2211.10435. https://arxiv.org/abs/2211.10435

34. Ghorbani, B., et al. "Scaling Laws for Neural Language Models." arXiv:2001.08361 (Referenced for scaling context). https://arxiv.org/abs/2001.08361

35. Kaplan, J., McCandlish, S., Henighan, T., Brown, T. B., Chess, B., Dohan, R., Gray, S., Radford, A., Sutskever, I., & Amodei, D. "Scaling Laws for Neural Language Models." *arXiv preprint*, 2020. arXiv:2001.08361. https://arxiv.org/abs/2001.08361

36. Huang, W., Xia, F., Xiao, T., Dickinson, B., Liang, Y., Hausman, P., Finn, C., & Levine, S. "Inner Monologue: Embodied Reasoning through Planning with Language Models." *CoRL 2023*. arXiv:2207.05608. https://arxiv.org/abs/2207.05608

37. Li, G. N., & Liang, P. "Selective Annotation Makes Language Models Better Few-Shot Learners." *EMNLP 2023*. arXiv:2109.11026. https://arxiv.org/abs/2109.11026

38. Press, O., Zhang, M., Min, S., Schmidt, L., Smith, N. A., & Lewis, M. "Measuring and Narrowing the Compositionality Gap in Language Models." *EMNLP 2023*. arXiv:2210.03350. https://arxiv.org/abs/2210.03350
## References

- Yao, S. et al., "ReAct: Synergizing Reasoning and Acting in Language Models," ICLR 2023. https://arxiv.org/abs/2210.03629
- Schick, T. et al., "Toolformer: Language Models Can Teach Themselves to Use Tools," 2023. https://arxiv.org/abs/2302.04761
- Wei, J. et al., "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models," NeurIPS 2022. https://arxiv.org/abs/2201.11903
- Mialon, G. et al., "Augmented Language Models: a Survey," 2023. https://arxiv.org/abs/2302.07842
- Wang, L. et al., "A Survey on Large Language Model based Autonomous Agents," 2023. https://arxiv.org/abs/2308.11432
- Park, J.S. et al., "Generative Agents: Interactive Simulacra of Human Behavior," UIST 2023. https://arxiv.org/abs/2304.03442
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
- LangChain Documentation. https://docs.langchain.com/
- OpenAI API Documentation. https://platform.openai.com/docs
- Anthropic Documentation. https://docs.anthropic.com
